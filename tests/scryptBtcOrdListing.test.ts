import { expect, use } from 'chai'
import { sha256, toByteString } from 'scrypt-ts'
import { OrdListing } from '../src/contracts/scryptBtcOrdListing'
import { getDefaultSigner } from './utils/txHelper'
import chaiAsPromised from 'chai-as-promised'
use(chaiAsPromised)

describe('Test SmartContract `ScryptBtcOrdListing`', () => {
    let instance: OrdListing

    before(async () => {
        await OrdListing.loadArtifact()

        instance = new OrdListing(toByteString('test', true))
        await instance.connect(getDefaultSigner())
    })

    it('should pass', async () => {
        console.log(instance.lockingScript.toASM())
    })
})
