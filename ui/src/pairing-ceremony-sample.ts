// SPDX-License-Identifier: GPL-2.0-or-later
// QA-ONLY sample code for the gallery. This is NOT a pairing invitation: it
// carries no nonce, challenge, identity, key, relay address or route, and no
// product path can produce or accept it. Scanning it yields the plain sentence
// below, which says so. Regenerate by encoding that text at EC level M.
//
//   uac-gallery-sample:not-a-real-invitation:TPRjVspOw5HO8CJ-lAFVb0QVpdIk4Ig6gKFpN_S4S1d5vIjqHLPFc8TH3rv6QCqmRcAkZN_QkziERyGGEm57Zx5xij8iqmPqBAPL1AX79cDsrCOH99XSl2-Ogr5I90P5FhTwZuWVlPiTTsCl5iM5LSYI7JAYftWp0ureGa-DXZ8FzUpJ1Ol-U2u0Gi2_ov99hoXnoH9KYW94eJMNmSXT7PzgSxX4pLj2Zw8sB1kTUFA3l6ahSteziHdOo9ApVwU06RNqHFEf1sOqctwziGSmhtbOZ46IcnirqkbwKUDY8zF1qWgnETWg43R8PbFFwFgME2du1QpyAK-g0tXjaFUyTkkmq4PsoKm25Hrdx7qF0_VrTdgHjvJhO5mi1PReDr_GcW_hwh2x_cTowxac72UgY9Vn5R1ua2JwsnzFBsvbAjxBhsKtD
//
// The grid is the 85 module rows of that encoding, packed row-major, one bit per
// module, high bit first, so the gallery renders the real geometry of the screen
// without ever holding a real invitation.
const PACKED =
  '/uklsYSh2PIFq/wVRFlrzTGjTfWQbpxq0e5xh6CH2Lt1INMCOqvDwpEl26Lsfvnww/kHti7BLLxcdWKcQ27pB/qqqqqq'
  + 'qqqqqq/gH5IjETQTETSBALcuSx+35E+s/ppYQnCGFEMOR4xk/tajtUIxHjDb74Yxa+RJnXAAjnU1lPp5OL35oF+o2ICz'
  + 'QFjdj6sOnQk0A1grqAAev1itusLU3JxtfRctDCgfyaCaMjINwV4OOsUsAwSiHcfK+VgpHnJz8wnH4ZSBOMKs/hgjUii0'
  + 'OG0L432XYGMLyzpAJofoday9QJ5KMO9wCt716hLxAQq0WuffZJgusGXCLpDhJ7fvb3L+WJ5X4MMIGSnmAqf4MDNcws1i'
  + 'joqB8TIQ1rzPgWXQx9cpDbaH7Xj+Ov1gYfhntf8sEP9cRQfEeMcESlwsWyvLRuohCCqVPOtzG0pxGebREJgbGt/TFU+1'
  + 'sA/ieE+5rcCfcCZAzy2gqsuSFmguUVEaP9do4mLLdeAv3Vpzkt8wHsN5xxiQPi1UKEDnuwuMN5Thh0FriyfZWdE+QeS1'
  + 'ahm9cwHXIqZNLPPa3y1HKDtN8qG0s+CFpM9UsB81g9Zlx6hg1BWfGoefj7FvJ1epIMobiSGTcoueLXwxIAetJGKprTiA'
  + 'NCxokwMgD6Adh9KGewKtOxclX4gpFXFNP1+1KicLa3qEntkgWSeo0gintKktW8W9LPHBeOtci1e1T0VhnOEKhbQBBbwM'
  + 'vfwgPvwl4f0iG/8kcoB8VAOMQlg0UaoWuCosLurdn+tpEUcdH60dH5ydGz+E5//1qz+HtO/H4aLsC+9AwxV0SVnrOUfr'
  + 'jJVufLOZg2VPxlCFt3peDG63htwfxR0CcM4rwI7G8lFOFlkgT9EquF7MD+4jL5AIUIL7lgk/3JBdROBL2lmFISy3HKFk'
  + 'kobxNDAi1sHtArPm5Vjum+zKezB+xiM02ls3EC1SqQSscUiT9ypyBEOCyRKRqqB2dijpnxYruVibDkS09r0bi5GHNgRH'
  + 'O/Fzy32M1wNCG1x36SWAzqnHPcfRGOuN05C+urICvCLUUDD9WSSpdIveyFcNJRz4GCZQnf5R4v+iXfuAZ1uUeMvMSwRk'
  + 'V/vtUiqB42uHCepwVHgVEFKdE5r3G7pJ7e/RlG+A1m/l1LpHBAtC5owgHW64n4xfORVbPPClBCW25mgC4nu/m0/sOXWa'
  + 'x1hM8owzgA==';

export const sampleQrWidth = 85;

export const sampleQrModules: readonly boolean[] = (() => {
  const bytes = Uint8Array.from(atob(PACKED), (character) => character.charCodeAt(0));
  const total = sampleQrWidth * sampleQrWidth;
  const modules = new Array<boolean>(total);
  for (let index = 0; index < total; index += 1) {
    modules[index] = (bytes[index >> 3]! >> (7 - (index % 8)) & 1) === 1;
  }
  return modules;
})();
