import java.security.PublicKey;
import java.util.HashSet;
import java.util.*;


public class TxHandler {

    private UTXOPool utxoPool;
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

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

            if (!Crypto.verifySignature(pubKey, tx.getRawDataToSign(i), in.signature))
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
