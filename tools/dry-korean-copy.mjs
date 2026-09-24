// SPDX-License-Identifier: GPL-2.0-or-later
// Mechanical migration of authored Korean presentation only. Catalog keys stay
// stable: they are identifiers shared by native and web renderers, not UI copy.
import { readFileSync, writeFileSync } from 'node:fs';

const endings = [
  ['비춰 주세요', '비추십시오'], ['기다려 주세요', '기다리십시오'],
  ['돌아와 주세요', '돌아오십시오'], ['눌러 주세요', '누르십시오'],
  ['열어 주세요', '여십시오'], ['풀어 주세요', '해제하십시오'],
  ['켜 주세요', '켜십시오'], ['꺼 주세요', '끄십시오'],
  ['해 주세요', '하십시오'], ['해주세요', '하십시오'],
  ['선택하세요', '선택하십시오'], ['확인하세요', '확인하십시오'],
  ['완료하세요', '완료하십시오'], ['정하세요', '설정하십시오'],
  ['여세요', '여십시오'], ['보세요', '확인하십시오'],
  ['기다리고 있어요', '기다리는 중입니다'], ['진행하고 있어요', '진행 중입니다'],
  ['준비하고 있어요', '준비 중입니다'], ['불러오고 있어요', '불러오는 중입니다'],
  ['확인하고 있어요', '확인 중입니다'], ['연결하고 있어요', '연결 중입니다'],
  ['정리하고 있어요', '정리 중입니다'], ['보내고 있어요', '전송 중입니다'],
  ['바꾸고 있어요', '변경 중입니다'], ['켜고 있어요', '켜는 중입니다'],
  ['열고 있어요', '여는 중입니다'], ['꺼져요', '꺼집니다'], ['켜져요', '켜집니다'],
  ['됐어요', '됐습니다'], ['돼요', '됩니다'], ['안 돼요', '안 됩니다'],
  ['표시할게요', '표시합니다'], ['앱이에요', '앱입니다'], ['상태예요', '상태입니다'],
  ['없었어요', '없었습니다'], ['있어요', '있습니다'], ['없어요', '없습니다'],
  ['않았어요', '않았습니다'], ['않아요', '않습니다'], ['못했어요', '못했습니다'],
  ['했어요', '했습니다'], ['지났어요', '지났습니다'], ['읽었어요', '읽었습니다'],
  ['필요해요', '필요합니다'], ['중요해요', '중요합니다'],
  ['사용해요', '사용합니다'], ['등록해요', '등록합니다'], ['실행해요', '실행합니다'],
  ['준비해요', '준비합니다'], ['해야 해요', '해야 합니다'], ['같아요', '같음'],
  ['있어야 해요', '있어야 합니다'], ['확인해요', '확인합니다'],
  ['끝났어요', '끝났습니다'], ['중이에요', '중입니다'], ['열려요', '열립니다'],
  ['따라 주세요', '따르십시오'], ['중지하세요', '중지하십시오'],
  ['하지 마세요', '하지 마십시오'], ['돌아가요', '돌아갑니다'],
  ['제거할까요?', '제거 확인'], ['해제할까요?', '해제 확인'],
  ['지울까요?', '삭제 확인'], ['다시 켤까요?', '다시 시작 확인'], ['끌까요?', '중지 확인'],
];
export function dryCopy(text) {
  text = text.replace(/UAC 원격 승인(?!기)/gu, 'UAC 원격 승인기');
  for (const [before, after] of endings) text = text.replaceAll(before, after);
  return text;
}

const path = 'locales/ko.json';
const catalog = JSON.parse(readFileSync(path, 'utf8'));
for (const key of Object.keys(catalog)) catalog[key] = dryCopy(catalog[key]);
// Fixed values for keys whose authored source still differs from the shown
// Korean. Only keys that still exist are touched, so a re-run never adds a
// retired key back. Keys whose source is already the shown text (the formal
// copy of the 1.5.1 cleanup, e.g. '휴대폰 승인 켜짐') have no override here:
// an override would turn them back into '서비스 …' wording.
const overrides = {
  'UAC 원격 승인': 'UAC 원격 승인기',
  '기다리는 요청이 없어요': '승인 요청 없음',
  '연결된 기기를 확인할 수 없어요': '연결 목록 확인 불가',
  '활동 기록을 확인할 수 없어요': '활동 기록 확인 불가',
  '숫자가 같아요': '숫자 일치',
  '활동 기록을 지울까요?': '활동 기록 삭제',
  'PC 또는 휴대폰의 응답을 기다리고 있어요.': 'PC 또는 휴대폰의 응답을 기다리는 중입니다.',
  'Windows의 처리 결과를 기다리고 있어요.': 'Windows 처리 결과 대기 중입니다.',
  '응답을 기다리고 있어요.': '응답 대기 중입니다.',
  '휴대폰 잠금 해제를 기다리고 있어요': '휴대폰 잠금 해제 대기 중',
  'PC의 UAC 원격 승인 앱에서 ‘휴대폰 관리’ → ‘UAC 원격 승인’을 눌러 QR 코드를 여세요. 아래 버튼을 누르면 이 앱에서 카메라가 열려요.': 'PC의 UAC 원격 승인기에서 ‘휴대폰 관리’ → ‘QR 코드 보기’를 선택하십시오. 아래 버튼으로 QR 코드를 촬영할 수 있습니다.',
};
for (const [key, value] of Object.entries(overrides)) if (Object.hasOwn(catalog, key)) catalog[key] = value;
writeFileSync(path, JSON.stringify(catalog, null, 2) + '\n');
const android = 'src-tauri/gen/android/app/src/main/res/values-ko/strings.xml';
writeFileSync(android, dryCopy(readFileSync(android, 'utf8')));
