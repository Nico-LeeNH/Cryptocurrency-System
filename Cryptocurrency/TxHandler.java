import java.security.PublicKey;
import java.util.HashSet;
import java.util.*;


public class TxHandler {

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent
     * transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the
     * UTXOPool(UTXOPool uPool)
     * constructor.
     */
    private UTXOPool utxoPool;
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     *         (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     *         (2) the signatures on each input of {@code tx} are valid,
     *         (3) no UTXO is claimed multiple times by {@code tx},
     *         (4) all of {@code tx}s output values are non-negative, and
     *         (5) the sum of {@code tx}s input values is greater than or equal to
     *         the sum of its output
     *         values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        double input = 0;
        double output = 0;
        HashSet<UTXO> usedUtxos = new HashSet<>();

        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);

            if (!utxoPool.contains(utxo))
                return false;

            Transaction.Output prevOutput = utxoPool.getTxOutput(utxo);

            PublicKey pubKey = prevOutput.address;
            byte[] rawData = tx.getRawDataToSign(i);
            byte[] signature = in.signature;

            if (!Crypto.verifySignature(pubKey, rawData, signature))
                return false;

            if (usedUtxos.contains(utxo))
                return false;
            usedUtxos.add(utxo);

            input += prevOutput.value;
        }

        for (Transaction.Output out : tx.getOutputs()) {
            if (out.value < 0)
                return false;
            output += out.value;
        }

        if (input < output)
            return false;

        return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        ArrayList<Transaction> accTxs = new ArrayList<>();
        boolean update = true;

        while (update) {
            update = false;

            for(Transaction tx : possibleTxs) {
                if (accTxs.contains(tx))
                    continue;
                
                if (isValidTx(tx)) {
                    accTxs.add(tx);
                    update = true;

                    for (Transaction.Input in : tx.getInputs()){
                        UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
                        utxoPool.removeUTXO(utxo);
                    }

                    byte[] txHash = tx.getHash();
                    for (int i = 0; i < tx.numOutputs(); i++){
                        UTXO newUTXO = new UTXO(txHash, i);
                        utxoPool.addUTXO(newUTXO, tx.getOutput(i));
                    }

                }
            }
        }
    return accTxs.toArray(new Transaction[0]);
    }

}
