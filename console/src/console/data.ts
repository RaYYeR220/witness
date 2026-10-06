/**
 * The console's data source and trusted lookups, provided once at the app
 * root so screens (and tests) can swap them.
 */

import { inject, type InjectionKey } from "vue";

import { createData, type WitnessData } from "@/api/client";
import { createLookups, type TrustedLookups } from "@/verify/lookups";

export const DATA_KEY: InjectionKey<WitnessData> = Symbol("witness-data");
export const LOOKUPS_KEY: InjectionKey<TrustedLookups> = Symbol("witness-lookups");

let data: WitnessData | null = null;
let lookups: TrustedLookups | null = null;

export function useData(): WitnessData {
  return inject(DATA_KEY, null) ?? (data ??= createData());
}

export function useLookups(): TrustedLookups {
  return inject(LOOKUPS_KEY, null) ?? (lookups ??= createLookups());
}
