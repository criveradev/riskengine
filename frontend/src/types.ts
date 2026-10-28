export type Page<T> = { items: T[]; total: number };
export type Audit = { id: string; name: string; scope: string; created_at?: string };
export type Report = { id: string; filename: string; finding_count: number; created_at: string; metadata: Record<string, string> };
export type Asset = { id: string; identifier: string; criticality: number | null; exposure: number | null };
export type CVEReview = { id?: number; cve: string; status: "pending" | "applicable" | "not_applicable"; reviewer: string | null; rationale: string | null; reviewed_at: string | null };
export type Finding = {
  id: string; external_id: string; import_id: string; asset_id: string; host: string; name: string;
  description: string; port: string; cves: string[]; cve_reviews?: CVEReview[]; severity: number | null; cvss: number | null;
  original_vectors?: string[] | null; cvss_admission?: { code: string; message: string }; vector: string | null; status: 'open' | 'reviewing' | 'resolved'; criticality: number | null; exposure: number | null;
};
export type Feature = 'cvss' | 'epss' | 'kev' | 'criticality' | 'exposure';
export type Run = { id: string; version: string; created_at: string; configuration: { profile_id?: string; weights: Record<Feature, number>; import_id: string; academic_status: string } };
export type RankingResult = { id: string; finding_id: string; status: string; score: number | null; explanation: string; snapshot: { finding: Finding; inputs: Record<Feature, number | boolean | null>; missing: string[]; contributions: Partial<Record<Feature, number>>; evidence: unknown[] } };
export type ResultPage = Page<RankingResult> & { run: Run };
