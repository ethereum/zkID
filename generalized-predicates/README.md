# Generalized Predicate Proofs for Verifiable Credentials

This design enables a credential holder to prove complex logical statements over multiple attributes without revealing the underlying values. Policies can express comparisons between an attribute and a constant or between two attributes of the same credential, range checks, set membership, non-membership, and arbitrary logical compositions of these. The verifier validates the proof and obtains the boolean result of the logical expression, which indicates whether the policy is satisfied.

This is particularly useful for privacy-preserving identity systems where users must prove eligibility conditions such as:

- `age >= 18`
- `employment_years >= 2 AND (50000 <= annual_income_eur <= 100000 OR account_balance_eur >= 10000)`
- `age >= 18 AND residency_country IN {"Netherlands","Belgium","Germany"}`
- `account_balance_eur >= loan_amount_eur`

The construction supports arbitrary logical composition while keeping all claims private.

# Inputs

The proving system receives three inputs:

1. List of claim values (private)
2. List of predicates (public)
3. Logical expression combining predicate results (public)

## 1. Claim Values

Claims are the private attributes stored inside the credential. These values are never revealed to the verifier.

Example:

```
claims = {
  date_of_birth: "1990-03-20",
  country: "Netherlands",
  annual_income_eur: 52000
}
```

So the claim values are `("1990-03-20", "Netherlands", 52000)`.

## 2. Predicates

Predicates are boolean conditions evaluated over claim values. Each predicate evaluates to either `true` or `false`.

Examples:

- `date_of_birth <= "2008-04-04"`
- `annual_income_eur >= 50000`
- `country == "Netherlands"`

Each predicate can be represented as:

```
predicate = (claim_index, operator, operand)
```

- `claim_index`: index to the claim value (left-hand side of comparison)
- `operator`: comparison operator
- `operand`: right-hand side of the comparison, either a constant value or a reference to another claim index

Supported predicate operators:

- `<=`
- `>=`
- `==`

From a theoretical perspective, `<` and `=` are sufficient to construct all comparison operators (combined with boolean NOT for negation).

In this design, all three operators are included directly for simplicity and optimization (fewer constraints).

Examples of rewrites:

- `<` can be rewritten as `<= (value - 1)`
- `>` can be rewritten as `>= (value + 1)`
- `!=` can be expressed as `NOT (==)` using logical composition

Restricting the operator set simplifies circuit construction and reduces constraint count.

### Example Predicate List

Credential reference:

```
claims = {
  date_of_birth: "2003-06-15",
  country: "Germany",
  annual_income_eur: 52000
}
```

Predicate list:

```
P0: date_of_birth <= "2008-04-04"
P1: annual_income_eur >= 50000
P2: country == "Netherlands"
```

Checking against the credential reference:

```
P0: "2003-06-15" <= "2008-04-04" -> true
P1: 52000 >= 50000               -> true
P2: "Germany" == "Netherlands"   -> false
```

Predicate results:

```
P0 -> true
P1 -> true
P2 -> false
```

## 3. Logical Expression

The logical expression combines predicate results using boolean operators.

Supported logical operators:

- AND
- OR
- NOT

From a theoretical perspective, `AND` and `NOT` are functionally complete, so all logical operators can be expressed using only those two.

In this design, `OR` is included explicitly for simplicity and optimization (fewer constraints).

# Why Postfix Notation is Used

Although users naturally write expressions in infix notation, postfix notation is used inside the circuit for several reasons:

1. No parentheses required
2. No operator precedence handling inside circuit
3. Deterministic evaluation order
4. Stack-based evaluation
5. No branching logic
6. Reduced circuit complexity

Infix notation requires parsing rules such as:

- precedence handling
- parentheses matching
- recursive evaluation

These operations are inefficient in zero-knowledge circuits because they require conditional branching and dynamic control flow.

Postfix notation removes all ambiguity and allows simple linear evaluation.

# Infix and Postfix Examples

Logical expression (infix):

```
A AND B
```

Logical expression (postfix):

```
A B AND
```

Complex example:

Logical expression (infix):

```
(A AND B) OR (C AND D)
```

Logical expression (postfix):

```
A B AND C D AND OR
```

# Conversion from Infix to Postfix

The conversion from infix to postfix is performed outside the circuit using the Shunting Yard algorithm, adapted to handle logical expressions and operators.

The circuit therefore evaluates only the postfix logical expression over predicate results, avoiding parsing and operator precedence handling inside the circuit.

The system assumes the provided postfix expression correctly represents the intended policy. Since the postfix expression is a public input, the verifier can independently validate that it is well-formed and corresponds to the expected policy before verifying the proof.

Example conversion:

Logical expression (infix):

`(date_of_birth <= "2008-04-04" AND annual_income_eur >= 50000) OR country == "Netherlands"`

Logical expression (postfix):

```
P0 P1 AND P2 OR
```

# Evaluation Flow

The proving process consists of two conceptual steps.

## Step 1: Predicate Evaluation

Claims:

```
date_of_birth = "2003-06-15"
annual_income_eur = 52000
country = "Germany"
```

Predicate definitions and results:

```
P0: date_of_birth <= "2008-04-04"   -> "2003-06-15" <= "2008-04-04" -> true
P1: annual_income_eur >= 50000      -> 52000 >= 50000               -> true
P2: country == "Netherlands"        -> "Germany" == "Netherlands"   -> false
```

Predicate results:

```
[ true, true, false ]
```

## Step 2: Logical Expression Evaluation

Logical expression (infix):

`(date_of_birth <= "2008-04-04" AND annual_income_eur >= 50000) OR country == "Netherlands"`

Logical expression (postfix):

```
P0 P1 AND P2 OR
```

Evaluation steps (processing the postfix expression from left to right, in a stack-based way):

```
1. Read P0   -> push true
2. Read P1   -> push true
3. Read AND  -> pop true, true; push true
4. Read P2   -> push false
5. Read OR   -> pop false, true; push true
```

Final result:

```
true
```

Only the final boolean value is revealed.

# Formal Model

Claims:

$$
C = (c_0, c_1, \ldots, c_n)
$$

Predicates:

$$
P_i = (j_i, \mathsf{op}_i, v_i), \quad i \in \{0, \ldots, m\}, \quad j_i \in \{0, \ldots, n\}, \quad \mathsf{op}_i \in \{\le, \ge, =\}
$$

where $j_i$ is the left-hand side claim index, and $v_i$ is the right-hand side operand, either a constant value $k_i$ or a reference to another claim index $j_i' \in \{0, \ldots, n\}$.

Note: the formal notation uses `=` for equality; the implementation-level notation uses `==`.

Predicate evaluation:

$$
\mathsf{rhs}_i = \begin{cases} k_i & \text{if } v_i \text{ is a constant } k_i \\ c_{j_i'} & \text{if } v_i \text{ is a claim reference } j_i' \end{cases}
$$

$$
r_i = \mathsf{op}_i(c_{j_i},\ \mathsf{rhs}_i) \in \{0,1\}, \quad i \in \{0, \ldots, m\}
$$

Predicate results:

$$
R = (r_0, r_1, \ldots, r_m)
$$

Logical expression (postfix notation):

$$
L = (\ell_0, \ell_1, \ldots, \ell_t)
$$

$$
\ell_q \in \{0, \ldots, m\} \cup \{\mathrm{AND}, \mathrm{OR}, \mathrm{NOT}\}, \quad q \in \{0, \ldots, t\}
$$

where elements in $\{0, \ldots, m\}$ are predicate result indices and the rest are boolean operators.

The prover generates a zero-knowledge proof that:

$$
b = E(L), \quad b \in \{0,1\}
$$

where $E$ is the stack-based postfix evaluation function that maps the expression $L$ to a single boolean value, without revealing $C$.

# Privacy Guarantees

The verifier learns:

- Logical expression (policy)
- Predicate definitions (claim indices, operators, and operands)
- Final boolean result

The verifier does not learn:

- Claim values
- Individual predicate results
- Intermediate evaluation steps

# Derived Predicate Patterns: Range, Membership, Non-Membership, and Claim-to-Claim

Common predicate patterns such as range checks, membership, non-membership, and claim-to-claim comparisons can be expressed through logical composition of basic predicates.

## Range Proofs

Range proofs allow proving that a value lies within an interval.

`30000 <= annual_income_eur <= 60000`

Predicates:

```
P0: annual_income_eur >= 30000
P1: annual_income_eur <= 60000
```

Logical expression (infix):

```
P0 AND P1
```

Logical expression (postfix):

```
P0 P1 AND
```

This proves the value lies in the range.

## Membership Proofs

Membership in a set.

`country == X OR country == Y OR country == Z`

Predicates:

```
P0: country == X
P1: country == Y
P2: country == Z
```

Logical expression (infix):

```
P0 OR P1 OR P2
```

Logical expression (postfix):

```
P0 P1 OR P2 OR
```

This proves the value belongs to the set without revealing which element.

## Non-Membership Proofs

Non-membership in a set.

`NOT (country == X) AND NOT (country == Y)`

Predicates:

```
P0: country == X
P1: country == Y
```

Logical expression (infix):

```
NOT P0 AND NOT P1
```

Logical expression (postfix):

```
P0 NOT P1 NOT AND
```

This proves the value is not in the forbidden set.

## Combining Range and Membership

Example policy:

"User is millennial and located in one of these EU countries: NL, BE, or DE"

Using ISO 8601 date-of-birth notation (`YYYY-MM-DD`):

`(date_of_birth >= "1981-01-01" AND date_of_birth <= "1996-12-31") AND (country == "NL" OR country == "BE" OR country == "DE")`

Predicates:

```
P0: date_of_birth >= "1981-01-01"
P1: date_of_birth <= "1996-12-31"
P2: country == "NL"
P3: country == "BE"
P4: country == "DE"
```

Logical expression (infix):

```
(P0 AND P1) AND (P2 OR P3 OR P4)
```

Logical expression (postfix):

```
P0 P1 AND P2 P3 OR P4 OR AND
```

This proves:

- user is millennial
- user country is one of these EU countries: NL, BE, or DE

without revealing any claim value.

## Claim-to-Claim Comparisons

When both sides of a comparison are credential attributes, the operand references another claim index instead of a constant. This allows expressing relations between claims directly.

Example policy:

"Loan amount does not exceed account balance"

`account_balance_eur >= loan_amount_eur`

Credential reference:

```
claims = {
  account_balance_eur: 15000,
  loan_amount_eur: 12000
}
```

Predicate:

```
P0: account_balance_eur >= loan_amount_eur
```

Logical expression (infix):

```
P0
```

Logical expression (postfix):

```
P0
```

The operand of `P0` is a claim reference (the index of `loan_amount_eur`) rather than a constant.

Evaluation:

```
15000 >= 12000 -> true
```

The verifier learns which two attributes are compared and the result, but not their values.

# Example: Age Verification

This example shows the complete flow for proving adulthood (>= 18) using a date-of-birth claim.

For this example, assume the current date is `2026-04-04`. The cutoff date is `2008-04-04`, calculated as the current date minus 18 years.

Given credential:

```
claims = {
  date_of_birth: "1990-03-20"
  // ... other credential claims
}
```

Predicate definition:

```
P0: date_of_birth <= "2008-04-04"
```

Logical expression (infix):

```
P0
```

Logical expression (postfix):

```
P0
```

Evaluation:

```
"1990-03-20" <= "2008-04-04" -> true
```

Result:

```
true
```

This verifies the holder is `>= 18` on `2026-04-04`, without revealing the exact date of birth.

When only one predicate is used the expression is just that predicate token, with no `AND`, `OR`, or `NOT` required.

# Design Notes and Extensions

The current design favors simplicity, auditability, and circuit efficiency. The following notes describe directions in which the design could be extended, and the trade-offs each direction introduces.

## Unified Evaluation in a Single Step

The current design separates evaluation into two conceptual steps: predicate evaluation followed by logical expression evaluation. These steps could be unified into one by treating comparison operators (`<=`, `>=`, `==`) and logical operators (`AND`, `OR`, `NOT`) as a single flat operator set evaluated over a shared stack. Claim values and constants would be pushed directly onto the stack, each operator would consume its operands and push a result, and no intermediate predicate result array would be required.

The shared stack would carry both numeric and boolean values: comparison operators consume non-boolean operands and produce a boolean, while logical operators consume booleans. Operators must therefore be type-aware, and the circuit must handle heterogeneous values uniformly. The current two-step design avoids this by keeping the logical expression evaluator operating purely over booleans, which is also more modular.

## Custom Operators

The operator set is not fixed. New operators can be defined to express common patterns more concisely. For example, a membership operator `IN` could take a claim index on the left-hand side and a list of claim indices or constant values on the right-hand side, evaluating directly to a boolean without expanding into a chain of `==` predicates combined with `OR`. This keeps the logical expression compact and makes the intent of the policy explicit.

Each new operator must be implemented inside the circuit, which introduces additional constraints. Adding an operator is therefore a trade-off between expressiveness and circuit cost: a custom operator can be cheaper than its expanded logical composition for frequently used patterns, but every operator included in the circuit contributes to its size regardless of whether a given proof uses it.

## Arithmetic Expressions

The design can be extended to support arithmetic operations such as addition, subtraction, and multiplication. Arithmetic operators would produce intermediate numeric values that comparison operators then consume to produce booleans. This allows policies over derived quantities, for example proving that the sum of two income sources exceeds a threshold:

`salary_eur + rental_income_eur >= 60000`

without revealing either value individually.

Each arithmetic operator included in the circuit introduces additional constraints, increasing circuit cost in exchange for greater expressiveness.
