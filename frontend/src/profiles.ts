import type { Feature } from './types';
export const profiles: Record<string, { label: string; weights: Record<Feature, number> }> = {
  'cvss-only-v1': { label: 'CVSS 3.1 solo', weights: { cvss: 1, epss: 0, kev: 0, criticality: 0, exposure: 0 } },
  'equal-weights-v1': { label: 'Cinco pesos iguales', weights: { cvss: .2, epss: .2, kev: .2, criticality: .2, exposure: .2 } },
  'roc-autores-v1': { label: 'ROC experimental', weights: { cvss: .04, epss: .26, kev: .46, criticality: .15, exposure: .09 } },
};
