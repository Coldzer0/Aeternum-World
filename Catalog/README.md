# Class mapper for Type Indexs


## What is inside (uuid_to_class.json)

This contains an array of UUIDs for each class that the game loads at runtime.

Example:

```JSON
"79C28008-4FC5-4EFB-88A1-538F4FB7DDE1": {
  "name": "MB::PositionInTheWorldReplicatedState",
  "is_empty_name": false,
  "type_idx": 13,
  "ida": {
    "vtable_va": "0x14846ae48",
    "caller_ra_va": "0x145c4e54a",
    "getter_va": null,
    "uuid_va": null,
    "name_va": null
  },
  "handler": {
    "Marshal": "0x1407F8B00",
    "Unmarshal": "0x145CE5F90",
    "CreateInstance": "0x1443988E0",
    "Destructor": "0x145BE3750"
  },
  "name_source": "javelin_rtti_static",
  "javelin_rtti": {
    "verdict": "MATCHED",
    "class": "PositionInTheWorldReplicatedState",
    "namespace": "MB",
    "full": "MB::PositionInTheWorldReplicatedState",
    "install_hook_addr": "0x14A22C500",
    "rtti_descriptor": "0x14A22C4F0",
    "stub": "0x145AE2A20",
    "vftable_base": "0x148456AA8",
    "lambda_invoke": "0x145AE2990",
    "get_type_descriptor": "0x145C4E3E0"
  }
}
```
There's 3 Interesting things here

1- type_idx in the main object.
2- vtable_va in "ida" object & Marshal - Unmarshal from "handler" Object.
3- The full name of the class in `javelin_rtti.full`.

To decode any packet you have to do RE for the Marshal & Unmarshal functions.

### So have fun.


## With ❤️ From Home.
