package dev.dkk115.uacremote

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import dev.dkk115.uacremote.background.ControllerForegroundService

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }

  override fun onStart() {
    super.onStart()
    // Opening/rotating the Activity must not undo an explicit service stop.
    ControllerForegroundService.startIfEnabled(this)
  }
}
