## Policy search order

An event is checked against every combination of the fields a policy can pin
down, narrowest first, and passes as soon as one of them is present in the
policy map. A blank cell means the lookup leaves that field at its wildcard
value.

These tables are not maintained by hand: the `SearchPolicyKey` and
`SearchIcmpPolicyKey` derives in `furui-macros` generate the lookups from the
`#[search_key]` attributes on the event structs, in field-declaration order.
`furui-common/src/event/mod.rs` asserts that the generated order still matches
what is written here.

### TCP and UDP

|     | protocol | local_port | remote_ip | remote_port |
|-----|:--------:|:----------:|:---------:|:-----------:|
| 1   |          |            |     ◯     |             |
| 2   |          |            |           |      ◯      |
| 3   |          |     ◯      |           |             |
| 4   |    ◯     |            |           |             |
| 5   |          |            |     ◯     |      ◯      |
| 6   |          |     ◯      |     ◯     |             |
| 7   |    ◯     |            |     ◯     |             |
| 8   |          |     ◯      |           |      ◯      |
| 9   |    ◯     |            |           |      ◯      |
| 10  |    ◯     |     ◯      |           |             |
| 11  |          |     ◯      |     ◯     |      ◯      |
| 12  |    ◯     |            |     ◯     |      ◯      |
| 13  |    ◯     |     ◯      |     ◯     |             |
| 14  |    ◯     |     ◯      |           |      ◯      |
| 15  |    ◯     |     ◯      |     ◯     |      ◯      |

### ICMP

|     | remote_ip | type | code |
|-----|:---------:|:----:|:----:|
| 1   |     ◯     |      |      |
| 2   |           |  ◯   |      |
| 3   |           |      |  ◯   |
| 4   |     ◯     |  ◯   |      |
| 5   |     ◯     |      |  ◯   |
| 6   |           |  ◯   |  ◯   |
| 7   |     ◯     |  ◯   |  ◯   |
