# How to produce and sign block

## Produce a candidate block

Any node running elements can produce a candidate block simply by running `getnewblockhex` with elements-cli.

Here's an example:  
`HEX=$(elements-cli getnewblockhex) // 000000203b8a1b9366c1b3dec7b60c0573e84a3d914c70fe2518c2faaa76b424af245ed3670ffdfaa18a47e4396b40e5cf826dbc46b9cb9bdef299c50672fe45a6740aeae85147600200000047522102ee2a1b14658ea816de9b38d349d14ad1239d3f46372b73f64a876c3683861c632102ff79dd3a26ee8509a068ac871fa09320c6062cbdd45e86784bc7f9605d15e53752ae00010200000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03520101ffffffff0201d96c5b7c306520a6860706c7406f5b6f6f8f24d8dd97188d4c41d886ed8c08cd01000000000000000000016a01d96c5b7c306520a6860706c7406f5b6f6f8f24d8dd97188d4c41d886ed8c08cd01000000000000000000266a24aa21a9ed94f15ed3a62165e4a0b99699cc28b48e19cb5bc1b1f47155db62d63f1e047d45000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000`

## Block validation script

The block validation script is a bitcoin script that is defined in the conf file. It defines the condition at which a block is valid for non-POW chain. 

It is defined by the `signblockscript` option in conf file. For example, adding the following line:  
`signblockscript=51 // OP_TRUE`  
...would make any block valid (as long as it is consensus compliant of course), since the script `OP_TRUE` is always valid by definition. 

The following script is slightly more complex:
`signblockscript=522102ee2a1b14658ea816de9b38d349d14ad1239d3f46372b73f64a876c3683861c632102ff79dd3a26ee8509a068ac871fa09320c6062cbdd45e86784bc7f9605d15e53752ae // OP_PUSHNUM_2 OP_PUSHBYTES_33 02ee2a1b14658ea816de9b38d349d14ad1239d3f46372b73f64a876c3683861c63 OP_PUSHBYTES_33 02ff79dd3a26ee8509a068ac871fa09320c6062cbdd45e86784bc7f9605d15e537 OP_PUSHNUM_2 OP_CHECKMULTISIG`

It means that a block can only be accepted as valid and added to the chain if it is signed by both private keys corresponding to those 2 public keys in the script. 

## Sign a block

The 2 block signers of the federation now need to sign the block with the `signblock` command:  
`SIGN=$(elements-cli signblock $HEX | jq -r .[0]) // { "pubkey": "02ee2a1b14658ea816de9b38d349d14ad1239d3f46372b73f64a876c3683861c63", "sig": "3044022042f86fe06534e8a85a17f33b30ec3947c6240ac401712c6b473641995e30cc5d02205afcf1991065efd7cd812a3b593efe20f8cc1c6e17a9de07e8818249894c7661" }`

The other signer must do the same and will get the other signature for the 2nd pubkey:  
`{ "pubkey": "02ff79dd3a26ee8509a068ac871fa09320c6062cbdd45e86784bc7f9605d15e537", "sig": "30440220521ac739d24f219fc674f5e5f1304859a37389db3cc689a1a7ab826ae9236d7802204ce03a236ee67327db3265a6a1bee3555337bf434a2bc6deb308512f150e4b20" }`

## Combine the signatures

Now someone needs to centralise both signatures (let's call this role "coordinator"). Once the coordinator has both signatures, he can combine them to produce a signed block like this :  
`BLOCK=$(elements-cli combineblocksigs $HEX "[$SIGN1,$SIGN2]" | jq -r .hex) // 000000203b8a1b9366c1b3dec7b60c0573e84a3d914c70fe2518c2faaa76b424af245ed3670ffdfaa18a47e4396b40e5cf826dbc46b9cb9bdef299c50672fe45a6740aea885247600200000047522102ee2a1b14658ea816de9b38d349d14ad1239d3f46372b73f64a876c3683861c632102ff79dd3a26ee8509a068ac871fa09320c6062cbdd45e86784bc7f9605d15e53752ae8f00463044022042f86fe06534e8a85a17f33b30ec3947c6240ac401712c6b473641995e30cc5d02205afcf1991065efd7cd812a3b593efe20f8cc1c6e17a9de07e8818249894c76614630440220521ac739d24f219fc674f5e5f1304859a37389db3cc689a1a7ab826ae9236d7802204ce03a236ee67327db3265a6a1bee3555337bf434a2bc6deb308512f150e4b20010200000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03520101ffffffff0201d96c5b7c306520a6860706c7406f5b6f6f8f24d8dd97188d4c41d886ed8c08cd01000000000000000000016a01d96c5b7c306520a6860706c7406f5b6f6f8f24d8dd97188d4c41d886ed8c08cd01000000000000000000266a24aa21a9ed94f15ed3a62165e4a0b99699cc28b48e19cb5bc1b1f47155db62d63f1e047d45000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000`

## Broadcast the block

If the block has enough signatures and that it satisfies any other conditions defined in the `signblockscript`, it is ready to be broadcasted to the whole network and added at the tip of our blockchain.

Anyone in possession of the signed block can do that with this command:  
`elements-cli submitblock $BLOCK`

## Risks and unanswered questions

1. Contrary to PoW, the federation can't guarantee that enough signers can't collude to reorg the chain. To prevent that, Liquid considers that any block is final, and this is enforced by the HSM that would refuse to sign any block that is deeper than 1 from the tip. How can we prevent that without HSM? What is the risk of signers cooperating to sign blocks and eventually reorg the chain?
