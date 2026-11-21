"""Optional constrained-output schema; never repairs or supplies model labels."""
from __future__ import annotations

SENTINELS = {'none', 'uncertain', 'unmapped'}
POSITIVE_LINKAGE = ['RCAT7.LINKAGE.EXPLICIT_CONTENT_DEPENDENCE', 'RCAT7.LINKAGE.IMPLICIT_OPERATION_DEPENDENCE']
PLAUSIBILITY = ['RCAT7.CONFOUND_PLAUSIBILITY.UNLIKELY', 'RCAT7.CONFOUND_PLAUSIBILITY.POSSIBLE', 'RCAT7.CONFOUND_PLAUSIBILITY.LIKELY', 'uncertain']
POLICY = 'rcat7-constrained-json-schema-v1'


def object_schema(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties), 'additionalProperties': False}


def proposal_schema(task, contract):
    handles = [item['handle'] for item in task['evidence']]
    def evidence(required=False):
        return {'type': 'array', 'items': {'type': 'string', 'enum': handles},
                'minItems': int(required), 'maxItems': len(handles)}
    def text(limit=1600):
        return {'type': 'string', 'minLength': 1, 'maxLength': limit}
    def label(axis, codes):
        variants = []
        for subset, required in [(sorted(set(codes) & SENTINELS), False),
                                 (sorted(set(codes) - SENTINELS), True)]:
            if subset:
                variants.append(object_schema({
                    'axis': {'const': axis}, 'code': {'type': 'string', 'enum': subset},
                    'confidence': {'type': 'integer', 'minimum': 0, 'maximum': 100},
                    'evidence_handles': evidence(required), 'rationale': text(),
                }))
        return variants[0] if len(variants) == 1 else {'anyOf': variants}
    branches = []
    mechanisms = sorted(set(contract.codes_by_axis['adaptation_mechanism']) - SENTINELS)
    for status, mechanism in [('mapped', code) for code in mechanisms] + [(s, s) for s in sorted(SENTINELS)]:
        axes = []
        for axis in contract.human_reviewed_axes:
            codes = contract.codes_by_axis[axis]
            if axis == 'adaptation_mechanism':
                codes = [mechanism]
            if axis == 'semantic_linkage':
                if status in {'mapped', 'unmapped'}:
                    codes = POSITIVE_LINKAGE
                elif status == 'none':
                    codes = ['none']
            axes.append(label(axis, codes))
        confounds = (set(contract.benign_confound_codes_by_mechanism[mechanism]) | {'uncertain', 'unmapped'}) if status == 'mapped' else {status}
        confound_variants = []
        for code in sorted(confounds):
            confound_variants.append(object_schema({
                'code': {'const': code},
                'plausibility': {'type': 'string', 'enum': ['uncertain'] if code in {'uncertain', 'unmapped'} else PLAUSIBILITY},
                'evidence_handles': evidence(code not in SENTINELS), 'rationale': text(),
            }))
        properties = {
            'mapping_status': {'const': status},
            'reviewed_axes': {'type': 'array', 'prefixItems': axes, 'minItems': 4, 'maxItems': 4},
            'locked_axes_hash': {'const': task['locked_axes_hash']},
            'benign_confound': {'anyOf': confound_variants}, 'rationale': text(2400),
        }
        if task['benchmark'] == 'T4':
            properties['affordance'] = object_schema({key: text() for key in
                ['defense_invariant', 'benign_exception', 'predicted_readaptation', 'evaluation_probe']})
        branches.append(object_schema(properties))
    return {'anyOf': branches}
