import {
    assert,
    ByteString,
    method,
    prop,
    PubKey,
    sha256,
    Sha256,
    Sig,
    SmartContract,
    toByteString,
} from 'scrypt-ts'

const TAG_HASH =
    'f40a48df4b2a70c8b4924bf2654661ed3d95fd66a313eb87237597c628e4a031' // sha256("BIP0340/challenge")
const Gx = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const PREIMAGE_SIGHASH = '00' // SIGHASH_ALL
const PREIMAGE_EPOCH = '00'

export type SHPreimage = {
    txVer: ByteString
    nLockTime: ByteString
    hashPrevouts: ByteString
    hashSpentAmounts: ByteString
    hashSpentScripts: ByteString
    hashSequences: ByteString
    hashOutputs: ByteString
    spendType: ByteString
    inputNumber: ByteString
    hashTapLeaf: ByteString
    keyVer: ByteString
    codeSeparator: ByteString

    sigHash: ByteString
    _e: ByteString // e without last byte
}

export class OrdListing extends SmartContract {
    // Data for checking sighash preimage:
    @prop()
    static readonly Gx: ByteString = toByteString(
        '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    )
    @prop()
    static readonly ePreimagePrefix: ByteString = toByteString(
        'f40a48df4b2a70c8b4924bf2654661ed3d95fd66a313eb87237597c628e4a031f40a48df4b2a70c8b4924bf2654661ed3d95fd66a313eb87237597c628e4a03179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179879be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    ) // TAG_HASH + TAG_HASH + Gx + Gx
    @prop()
    static readonly preimagePrefix: ByteString = toByteString(
        'f40a48df4b2a70c8b4924bf2654661ed3d95fd66a313eb87237597c628e4a031f40a48df4b2a70c8b4924bf2654661ed3d95fd66a313eb87237597c628e4a0310000'
    ) // TAG_HASH + TAG_HASH + PREIMAGE_SIGHASH + PREIMAGE_EPOCH

    @prop()
    paymentOutput: ByteString

    /**
     *
     * @param paymentOutput  - Serialized output that pays seller.
     */
    constructor(paymentOutput: ByteString) {
        super(...arguments)
        this.paymentOutput = paymentOutput
    }

    @method()
    public unlock(
        shPreimage: SHPreimage,
        ordDestOutput: ByteString,
        changeOutput: ByteString
    ) {
        // Check sighash preimage.
        this.checkSHPreimage(shPreimage)

        // Construct outputs and compare against hash in sighash preimage.
        const hashOutputs = sha256(
            this.paymentOutput + ordDestOutput + changeOutput
        )
        assert(hashOutputs == shPreimage.hashOutputs, 'hashOutputs mismatch')
    }

    @method()
    private checkSHPreimage(shPreimage: SHPreimage): void {
        const e = sha256(OrdListing.ePreimagePrefix + shPreimage.sigHash)
        assert(e == shPreimage._e + toByteString('01'), 'invalid value of _e')
        const s = OrdListing.Gx + shPreimage._e + toByteString('02')
        assert(this.checkSig(Sig(s), PubKey(OrdListing.Gx)))
        const sigHash = sha256(
            shPreimage.txVer +
                shPreimage.nLockTime +
                shPreimage.hashPrevouts +
                shPreimage.hashSpentAmounts +
                shPreimage.hashSpentScripts +
                shPreimage.hashSequences +
                shPreimage.hashOutputs +
                shPreimage.spendType +
                shPreimage.inputNumber +
                shPreimage.hashTapLeaf +
                shPreimage.keyVer +
                shPreimage.codeSeparator
        )
        assert(sigHash == shPreimage.sigHash, 'sigHash mismatch')
    }
}
