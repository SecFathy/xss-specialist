# XSS Specialist — Model Comparison

Same frozen XSSBench for every condition. Metrics: acc, vulnerable-class F1, false-positive rate (safe called vulnerable), false-negative rate, execution-context accuracy, abstention. Near-miss adds leakage (lower better) and anchor correctness.


### dev

| Condition | acc | F1 | FPR | FNR | ctx | abst |
|---|---|---|---|---|---|---|
| A | 0.794 | 0.794 | 0.270 | 0.129 | 0.516 | 0.000 |
| B | 0.912 | 0.912 | 0.162 | 0.000 | 0.387 | 0.000 |
| C | 0.941 | 0.931 | 0.000 | 0.129 | 1.000 | 0.000 |
| D | 0.897 | 0.873 | 0.000 | 0.226 | 1.000 | 0.000 |

### generalization

| Condition | acc | F1 | FPR | FNR | ctx | abst |
|---|---|---|---|---|---|---|
| A | 0.762 | 0.722 | 0.095 | 0.381 | 0.000 | 0.000 |
| B | 0.833 | 0.857 | 0.333 | 0.000 | 0.190 | 0.000 |
| C | 0.595 | 0.320 | 0.000 | 0.810 | 1.000 | 0.000 |
| D | 0.810 | 0.818 | 0.238 | 0.143 | 1.000 | 0.000 |

### nearmiss

| Condition | acc | F1 | FPR | FNR | ctx | abst | leak | anchor |
|---|---|---|---|---|---|---|---|---|
| A | 0.027 | 0.000 | 0.000 | 1.000 | 0.000 | 0.000 | 1.000 | True |
| B | 0.027 | 0.000 | 0.000 | 1.000 | 0.000 | 0.000 | 1.000 | True |
| C | 0.027 | 0.000 | 0.000 | 1.000 | 1.000 | 0.000 | 1.000 | True |
| D | 0.027 | 0.000 | 0.000 | 1.000 | 1.000 | 0.000 | 1.000 | True |

### adversarial

| Condition | acc | F1 | FPR | FNR | ctx | abst |
|---|---|---|---|---|---|---|
| A | 0.500 | 0.333 | 0.250 | 0.750 | 0.000 | 0.000 |
| B | 0.625 | 0.667 | 0.500 | 0.250 | 0.000 | 0.000 |
| C | 0.625 | 0.400 | 0.000 | 0.750 | 0.500 | 0.000 |
| D | 0.375 | 0.286 | 0.500 | 0.750 | 0.500 | 0.000 |

## Paired bootstrap: C − A (accuracy Δ, 95% CI)

| split | Δacc | 95% CI | n |
|---|---|---|---|
| dev | +0.147 * | [+0.044, +0.265] | 68 |
| generalization | -0.167 * | [-0.310, -0.024] | 42 |
| nearmiss | +0.000 | [+0.000, +0.000] | 37 |
| adversarial | +0.125 | [+0.000, +0.375] | 8 |

\* CI excludes 0 (significant at 95%).
