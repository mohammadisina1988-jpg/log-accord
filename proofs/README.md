# LogAccord StudioNet proofs

Verified 11 finalized receipts across two deployments, with 6 successful calls and 5 expected rejections.

| Scenario | Address | Deployment | Result | Workflow |
|---|---|---|---|---|
| valid | [Contract](https://explorer-studio.genlayer.com/address/0x2E2621D15B5399eFe3dCEca4aE3A88Fc69b155f4) | [Deploy](https://explorer-studio.genlayer.com/tx/0xbc458fafadcf2b961bdb1576497f8fe204118b1b7644169cbbb6571aabf66979) | [Result](https://explorer-studio.genlayer.com/tx/0xf85a0649d82170106d7c60a8406f7ce1973b951896120b7badd53fc2260f1779) | [Run](https://github.com/mohammadisina1988-jpg/log-accord/actions/runs/43285511898) |
| forged | [Contract](https://explorer-studio.genlayer.com/address/0x4637645904B30c3Eeff316f676EB7D9E9F061e12) | [Deploy](https://explorer-studio.genlayer.com/tx/0x22578c650bb860b48114dcf8cfaa4dc951aa2706af46620cea40655dbc7fe137) | [Result](https://explorer-studio.genlayer.com/tx/0x5f51d56f55e437726974c38b1ebd9bc3e51f3f71ec067003c993083c0c7e08d8) | [Run](https://github.com/mohammadisina1988-jpg/log-accord/actions/runs/43285523835) |

The valid instance advanced from three leaves to 3,501,950,757 leaves, then verified one public CT entry and an earlier prefix.
The forged instance rejected the modified root and retained zero checkpoints.

Source SHA-256: `5d5eedf264ddbfd118a9bc88bc516a68c744aceb9c4d218d7b05821ee5297a48`.
Fixture commit: `43f2a134b3518af4e4a9334d0c381d10b058f0ce`.
