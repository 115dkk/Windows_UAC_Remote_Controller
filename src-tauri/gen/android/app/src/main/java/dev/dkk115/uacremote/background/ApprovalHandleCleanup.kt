// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

internal enum class ApprovalCleanupAction {
    CLOSE_SUBMISSION,
    RETIRE,
    CLOSE_ATTEMPT,
    CLOSE_PLAN,
    COMPLETE,
}

/** Order is the diagnostic record. Append only. */
internal enum class ApprovalCleanupRefusal {
    NOT_TERMINAL,
    JOBS_OUTSTANDING,
    OPERATION_BUSY,
    EARLIER_FAILURE,
    ALREADY_QUEUED,
    ADMISSION_WAIT,
}

internal interface ApprovalCleanupPlatform<Plan, Attempt, Submission, Operation> {
    fun closeSubmission(submission: Submission)
    fun retire(plan: Plan)
    fun closeAttempt(attempt: Attempt)
    fun closePlan(plan: Plan)
    fun operationQuiescent(operation: Operation): Boolean
    fun cancelPlan(plan: Plan)
    fun planCancelled(plan: Plan): Boolean
    fun retirementBusy(failure: Throwable): Boolean
}

/**
 * Owns the conditions that admit cleanup together with every resource cleanup
 * may release. A successful action advances once; an exception leaves that
 * exact resource selected. The caller can request progress but cannot select or
 * report individual cleanup actions.
 */
internal class ApprovalCleanupOwner<Plan, Attempt, Submission, Operation>(
    private val platform: ApprovalCleanupPlatform<Plan, Attempt, Submission, Operation>,
    private val enqueue: (() -> Unit) -> Boolean,
    private val defer: (Long, () -> Unit) -> Boolean,
    private val onComplete: (Int) -> Unit,
    private val onRefused: (ApprovalCleanupRefusal) -> Unit = {},
    private val onFailure: (ApprovalCleanupAction, Throwable, Boolean) -> Unit = { _, _, _ -> },
    private val onRetireBusy: () -> Unit = {},
    private val onWakeRejected: () -> Unit = {},
    private val onProgress: () -> Unit = {},
) {
    private val lock = Any()
    private val admission = ApprovalCleanupAdmission()
    private val refusals = mutableSetOf<ApprovalCleanupRefusal>()
    private var plan: Plan? = null
    private var attempt: Attempt? = null
    private var submission: Submission? = null
    private var operation: Operation? = null
    private var nextAction = ApprovalCleanupAction.RETIRE
    private var terminal = false
    private var jobs = 0
    private var cleanupQueued = false
    private var cleanupFailed = false
    private var admissionWaiting = false
    private var cleanupComplete = false
    private var failureTraced = false
    private var cancellationUncertain = false
    private var failureRetries = 0

    fun bindPlan(value: Plan) = synchronized(lock) {
        check(plan == null)
        plan = value
    }

    fun bindAttempt(value: Attempt) = synchronized(lock) {
        check(attempt == null)
        attempt = value
    }

    fun bindOperation(value: Operation) = synchronized(lock) {
        check(operation == null)
        operation = value
    }

    fun plan(): Plan? = synchronized(lock) { plan }
    fun attempt(): Attempt? = synchronized(lock) { attempt }
    fun operation(): Operation? = synchronized(lock) { operation }

    fun holdSubmission(value: Submission): Boolean = synchronized(lock) {
        if (submission != null || cleanupComplete) false
        else {
            submission = value
            true
        }
    }

    fun takeSubmission(): Submission? = synchronized(lock) {
        submission.also { submission = null }
    }

    fun discardSubmission(value: Submission): Boolean = synchronized(lock) {
        if (submission !== value) false
        else {
            submission = null
            true
        }
    }

    fun submissionReleased(): Boolean = synchronized(lock) { submission == null }

    fun terminal() = synchronized(lock) { terminal = true }

    fun jobStarted() = synchronized(lock) { jobs++ }

    fun jobFinished(): Int = synchronized(lock) {
        check(jobs > 0)
        --jobs
    }

    fun jobs(): Int = synchronized(lock) { jobs }
    fun failed(): Boolean = synchronized(lock) { cleanupFailed }
    fun complete(): Boolean = synchronized(lock) { cleanupComplete }
    fun handlesClosed(): Boolean = synchronized(lock) { nextAction == ApprovalCleanupAction.COMPLETE }
    fun cancellationUncertain(): Boolean = synchronized(lock) { cancellationUncertain }

    fun retryFailed(maxRetries: Int): Boolean = synchronized(lock) {
        if (!cleanupFailed || failureRetries >= maxRetries) false
        else {
            failureRetries++
            cleanupFailed = false
            true
        }
    }

    fun retryExplicitly() = synchronized(lock) { cleanupFailed = false }

    /** Returns a caught cancellation failure; the downward-only state stays owned here. */
    fun cancelPlan(explicitRetry: Boolean): Throwable? = synchronized(lock) {
        if (nextAction == ApprovalCleanupAction.COMPLETE || cancellationUncertain && !explicitRetry) return@synchronized null
        try {
            plan?.let(platform::cancelPlan)
            cancellationUncertain = false
            null
        } catch (failure: Throwable) {
            cancellationUncertain = true
            failure
        }
    }

    fun planCancelledOrClosed(): Boolean = synchronized(lock) {
        if (nextAction == ApprovalCleanupAction.COMPLETE) true
        else try {
            plan?.let(platform::planCancelled) != false
        } catch (_: Exception) {
            true
        }
    }

    fun operationQuiescent(): Boolean = synchronized(lock) {
        operation?.let(platform::operationQuiescent) != false
    }

    fun requestCleanup() {
        val refusal = synchronized(lock) {
            when {
                cleanupComplete -> return
                !terminal -> ApprovalCleanupRefusal.NOT_TERMINAL
                jobs != 0 -> ApprovalCleanupRefusal.JOBS_OUTSTANDING
                operation?.let(platform::operationQuiescent) == false -> ApprovalCleanupRefusal.OPERATION_BUSY
                admissionWaiting -> ApprovalCleanupRefusal.ADMISSION_WAIT
                cleanupFailed -> ApprovalCleanupRefusal.EARLIER_FAILURE
                cleanupQueued -> ApprovalCleanupRefusal.ALREADY_QUEUED
                else -> {
                    cleanupQueued = true
                    null
                }
            }
        }
        if (refusal != null) {
            val first = synchronized(lock) { refusals.add(refusal) }
            if (first) onRefused(refusal)
            return
        }
        if (!enqueue { runCleanup() }) synchronized(lock) { cleanupQueued = false }
    }

    private fun runCleanup() {
        var failureAction = ApprovalCleanupAction.CLOSE_SUBMISSION
        try {
            val completionWaits = try {
                synchronized(lock) {
                    submission?.let { held ->
                        platform.closeSubmission(held)
                        submission = null
                    }
                    while (nextAction != ApprovalCleanupAction.COMPLETE) {
                        failureAction = nextAction
                        when (nextAction) {
                            ApprovalCleanupAction.CLOSE_SUBMISSION -> error("Submission is handled before the resource cursor")
                            ApprovalCleanupAction.RETIRE -> plan?.let(platform::retire)
                            ApprovalCleanupAction.CLOSE_ATTEMPT -> attempt?.let(platform::closeAttempt)
                            ApprovalCleanupAction.CLOSE_PLAN -> plan?.let(platform::closePlan)
                            ApprovalCleanupAction.COMPLETE -> Unit
                        }
                        nextAction = next(nextAction)
                    }
                    cleanupComplete = true
                    admission.waits()
                }
            } catch (failure: Throwable) {
                if (failureAction == ApprovalCleanupAction.RETIRE && platform.retirementBusy(failure)) {
                    waitForRetirementAdmission()
                } else {
                    val first = synchronized(lock) {
                        cleanupFailed = true
                        cleanupQueued = false
                        (!failureTraced).also { failureTraced = true }
                    }
                    onFailure(failureAction, failure, first)
                }
                return
            }
            onComplete(completionWaits)
        } finally {
            onProgress()
        }
    }

    private fun waitForRetirementAdmission() {
        val first: Boolean
        val delay: Long
        synchronized(lock) {
            admissionWaiting = true
            cleanupQueued = false
            first = admission.waits() == 0
            delay = admission.defer()
        }
        if (first) onRetireBusy()
        val posted = try {
            defer(delay) { wakeRetirementAdmission() }
        } catch (_: Exception) {
            false
        }
        if (!posted) {
            synchronized(lock) {
                admissionWaiting = false
                cleanupFailed = true
            }
            onWakeRejected()
        }
    }

    private fun wakeRetirementAdmission() {
        val wake = synchronized(lock) {
            if (!admissionWaiting || cleanupComplete) false
            else {
                admissionWaiting = false
                true
            }
        }
        if (wake) requestCleanup()
    }

    private fun next(action: ApprovalCleanupAction): ApprovalCleanupAction = when (action) {
        ApprovalCleanupAction.CLOSE_SUBMISSION -> ApprovalCleanupAction.RETIRE
        ApprovalCleanupAction.RETIRE -> ApprovalCleanupAction.CLOSE_ATTEMPT
        ApprovalCleanupAction.CLOSE_ATTEMPT -> ApprovalCleanupAction.CLOSE_PLAN
        ApprovalCleanupAction.CLOSE_PLAN -> ApprovalCleanupAction.COMPLETE
        ApprovalCleanupAction.COMPLETE -> ApprovalCleanupAction.COMPLETE
    }
}
