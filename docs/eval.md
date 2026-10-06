# Evaluation

## Proof compatibility

`witness_core.poi_compat.to_inx_poi` emits the inx-poi proof JSON
(`{"l": .., "r": ..}` with `{"h": ..}` for hashed subtrees and `{"value": ..}`
for the proven leaf). Two checks against real HORNET 2.0.2 captures:

- Offline: for every entry in `poi_create.json`, `to_inx_poi(cone, index)` is
  structurally equal to the proof inx-poi itself produced, and the decoded path
  verifies against the milestone's `inclusionMerkleRoot`.
- Live: each of the 4 captured `{milestone, block, proof}` bodies was POSTed to
  `http://127.0.0.1:14265/api/poi/v1/validate` with `proof` replaced by our
  `to_inx_poi` output. Result: `{"valid":true}` for 4/4. With the leaf value
  altered in the same proof, 4/4 returned `{"valid":false}`.
