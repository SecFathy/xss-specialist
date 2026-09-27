# XSS Specialist — Model Comparison

Same frozen XSSBench for every condition. Metrics: acc, vulnerable-class F1, false-positive rate (safe called vulnerable), false-negative rate, execution-context accuracy, abstention. Near-miss adds leakage (lower better) and anchor correctness.


### dev

| Condition | acc | F1 | FPR | FNR | ctx | abst |
|---|---|---|---|---|---|---|
| A_base | 0.794 | 0.794 | 0.270 | 0.129 | 0.516 | 0.000 |
| B_base_rag | 0.912 | 0.912 | 0.162 | 0.000 | 0.387 | 0.000 |
| C_v1 | 0.941 | 0.931 | 0.000 | 0.129 | 1.000 | 0.000 |
| E_v2 | 1.000 | 1.000 | 0.000 | 0.000 | 1.000 | 0.000 |
| F_v3 | 1.000 | 1.000 | 0.000 | 0.000 | 0.903 | 0.000 |

### generalization

| Condition | acc | F1 | FPR | FNR | ctx | abst |
|---|---|---|---|---|---|---|
| A_base | 0.762 | 0.722 | 0.095 | 0.381 | 0.000 | 0.000 |
| B_base_rag | 0.833 | 0.857 | 0.333 | 0.000 | 0.190 | 0.000 |
| C_v1 | 0.595 | 0.320 | 0.000 | 0.810 | 1.000 | 0.000 |
| E_v2 | 0.905 | 0.895 | 0.000 | 0.190 | 1.000 | 0.000 |
| F_v3 | 0.714 | 0.600 | 0.000 | 0.571 | 1.000 | 0.000 |

### nearmiss

| Condition | acc | F1 | FPR | FNR | ctx | abst | leak | anchor |
|---|---|---|---|---|---|---|---|---|
| A_base | 0.027 | 0.000 | 0.000 | 1.000 | 0.000 | 0.000 | 1.000 | True |
| B_base_rag | 0.027 | 0.000 | 0.000 | 1.000 | 0.000 | 0.000 | 1.000 | True |
| C_v1 | 0.027 | 0.000 | 0.000 | 1.000 | 1.000 | 0.000 | 1.000 | True |
| E_v2 | 0.027 | 0.000 | 0.000 | 1.000 | 1.000 | 0.000 | 1.000 | True |
| F_v3 | 0.027 | 0.000 | 0.000 | 1.000 | 1.000 | 0.000 | 1.000 | True |

### adversarial

| Condition | acc | F1 | FPR | FNR | ctx | abst |
|---|---|---|---|---|---|---|
| A_base | 0.500 | 0.333 | 0.250 | 0.750 | 0.000 | 0.000 |
| B_base_rag | 0.625 | 0.667 | 0.500 | 0.250 | 0.000 | 0.000 |
| C_v1 | 0.625 | 0.400 | 0.000 | 0.750 | 0.500 | 0.000 |
| E_v2 | 0.625 | 0.571 | 0.250 | 0.500 | 0.750 | 0.000 |
| F_v3 | 0.625 | 0.400 | 0.000 | 0.750 | 0.750 | 0.000 |

## Paired bootstrap: E_v2 − A_base (accuracy Δ, 95% CI)

| split | Δacc | 95% CI | n |
|---|---|---|---|
| dev | +0.206 * | [+0.118, +0.309] | 68 |
| generalization | +0.143 * | [+0.048, +0.262] | 42 |
| nearmiss | +0.000 | [+0.000, +0.000] | 37 |
| adversarial | +0.125 | [+0.000, +0.375] | 8 |

\* CI excludes 0 (significant at 95%).
