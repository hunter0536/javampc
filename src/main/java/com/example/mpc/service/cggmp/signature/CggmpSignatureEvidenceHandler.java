package com.example.mpc.service.cggmp.signature;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.PiAffGProof;
import com.example.mpc.cggmp.proof.PiDecProof;
import com.example.mpc.cggmp.proof.PresignProofs;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.Gg20SignatureTask;
import com.example.mpc.service.CggmpSignatureService;
import com.example.mpc.service.NodeService;
import com.example.mpc.service.cggmp.CggmpCodecUtils;
import com.example.mpc.service.cggmp.CggmpProtocolUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public final class CggmpSignatureEvidenceHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpSignatureEvidenceHandler.class);
    private final CggmpSignatureService svc;

    public CggmpSignatureEvidenceHandler(CggmpSignatureService svc) {
        this.svc = svc;
    }


    Map<String, Object> buildDecEvidenceDelta(Gg20SignatureTask task, BigInteger gamma_i, BigInteger delta_i) {
        try {
            BigInteger K = task.presignK.get(svc.nodeId);
            if (K == null) return null;
            BigInteger D = computePresignDForSelf(task, task.presignD, task.presignFOutgoing);
            if (D == null) return null;
            ECPoint Gamma = task.presignGamma.get(svc.nodeId);
            if (Gamma == null) {
                Gamma = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), gamma_i);
            }
            ECPoint S = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), delta_i);
            BigInteger nSquared = task.paillier.getPublicKeyInfo().nSquared();
            BigInteger c = task.paillier.getPublicKeyInfo().multiply(K, gamma_i).multiply(D).mod(nSquared);
            BigInteger rho = task.paillier.recoverRandomizer(c, delta_i);
            PiDecProof proof = PresignProofs.createDecProof(
                    Secp256k1CurveUtils.G(),
                    Gamma,
                    S,
                    task.paillier.getPublicKeyInfo().n(),
                    K,
                    D,
                    gamma_i,
                    delta_i,
                    rho,
                    svc.proofKappa,
                    svc.proofEpsBits,
                    CggmpProtocolUtils.buildPresignContext(task.taskId, svc.nodeId, "DEC")
            );
            Map<String, Object> ev = new HashMap<>();
            ev.put("piDecProof", CggmpCodecUtils.encodePiDecProof(proof));
            ev.put("K", HexUtils.toHex(K));
            ev.put("D", HexUtils.toHex(D));
            ev.put("Gamma", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(Gamma)));
            ev.put("S", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(S)));
            Map<String, Object> affg = buildAffGEvidenceDelta(task, gamma_i);
            if (affg != null && !affg.isEmpty()) {
                ev.putAll(affg);
            }
            return ev;
        } catch (Exception e) {
            logger.warn("Failed to build PiDec delta evidence: {}", e.getMessage());
            return null;
        }
    }

    Map<String, Object> buildDecEvidenceChi(Gg20SignatureTask task, BigInteger x_i, BigInteger chi_i) {
        try {
            BigInteger K = task.presignK.get(svc.nodeId);
            if (K == null) return null;
            BigInteger Dhat = computePresignDForSelf(task, task.presignDhat, task.presignFhatOutgoing);
            if (Dhat == null) return null;
            ECPoint Gamma = CggmpProtocolUtils.sumPresignGamma(task);
            ECPoint X_i = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), x_i);
            ECPoint S = Gamma.multiply(chi_i).normalize();
            BigInteger nSquared = task.paillier.getPublicKeyInfo().nSquared();
            BigInteger c = task.paillier.getPublicKeyInfo().multiply(K, x_i).multiply(Dhat).mod(nSquared);
            BigInteger rho = task.paillier.recoverRandomizer(c, chi_i);
            PiDecProof proof = PresignProofs.createDecProof(
                    Secp256k1CurveUtils.G(),
                    Gamma,
                    S,
                    task.paillier.getPublicKeyInfo().n(),
                    K,
                    Dhat,
                    x_i,
                    chi_i,
                    rho,
                    svc.proofKappa,
                    svc.proofEpsBits,
                    CggmpProtocolUtils.buildPresignContext(task.taskId, svc.nodeId, "DEC")
            );
            Map<String, Object> ev = new HashMap<>();
            ev.put("piDecProof", CggmpCodecUtils.encodePiDecProof(proof));
            ev.put("K", HexUtils.toHex(K));
            ev.put("D", HexUtils.toHex(Dhat));
            ev.put("Gamma", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(Gamma)));
            ev.put("S", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(S)));
            ev.put("X", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(X_i)));
            Map<String, Object> affg = buildAffGEvidenceChi(task, x_i);
            if (affg != null && !affg.isEmpty()) {
                ev.putAll(affg);
            }
            return ev;
        } catch (Exception e) {
            logger.warn("Failed to build PiDec chi evidence: {}", e.getMessage());
            return null;
        }
    }

    boolean verifyDecEvidence(Gg20SignatureTask task, int senderId, Map<?, ?> evidence) {
        try {
            if (!verifyDecEvidenceConsistency(task, senderId, evidence)) {
                return false;
            }
            Map<?, ?> proofMap = (Map<?, ?>) evidence.get("piDecProof");
            String kHex = (String) evidence.get("K");
            String dHex = (String) evidence.get("D");
            String gammaHex = (String) evidence.get("Gamma");
            String sHex = (String) evidence.get("S");
            if (proofMap == null || kHex == null || dHex == null || gammaHex == null || sHex == null) {
                return false;
            }
            PiDecProof proof = CggmpCodecUtils.decodePiDecProof(proofMap);
            BigInteger K = new BigInteger(kHex, 16);
            BigInteger D = new BigInteger(dHex, 16);
            ECPoint Gamma = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(gammaHex));
            ECPoint S = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(sHex));
            if (proof.A() == null || proof.B() == null || proof.C() == null
                    || proof.z() == null || proof.w() == null || proof.nu() == null) {
                return false;
            }
            if (proof.A().isEmpty() || proof.B().isEmpty() || proof.C().isEmpty()
                    || proof.z().isEmpty() || proof.w().isEmpty() || proof.nu().isEmpty()) {
                return false;
            }
            return PresignProofs.verifyDecProof(
                    proof,
                    Secp256k1CurveUtils.G(),
                    Gamma,
                    S,
                    task.paillier.getPublicKeyInfo().n(),
                    K,
                    D,
                    svc.proofKappa,
                    svc.proofEpsBits,
                    CggmpProtocolUtils.buildPresignContext(task.taskId, senderId, "DEC"));
        } catch (Exception e) {
            logger.warn("Failed to verify PiDec evidence: {}", e.getMessage());
            return false;
        }
    }

    boolean verifyDecEvidenceConsistency(Gg20SignatureTask task, int senderId, Map<?, ?> evidence) {
        String dHex = (String) evidence.get("D");
        if (dHex == null) {
            return false;
        }
        BigInteger claimedD = new BigInteger(dHex, 16);
        Map<?, ?> dMap = (Map<?, ?>) evidence.get("D_map");
        Map<?, ?> fMap = (Map<?, ?>) evidence.get("F_map");
        Map<?, ?> dhMap = (Map<?, ?>) evidence.get("Dhat_map");
        Map<?, ?> fhMap = (Map<?, ?>) evidence.get("Fhat_map");
        if (dMap != null && fMap != null) {
            return verifyDecEvidenceConsistencyMap(task, senderId, claimedD, dMap, fMap);
        }
        if (dhMap != null && fhMap != null) {
            return verifyDecEvidenceConsistencyMap(task, senderId, claimedD, dhMap, fhMap);
        }
        return true;
    }

    boolean verifyDecEvidenceConsistencyMap(Gg20SignatureTask task,
                                           int senderId,
                                           BigInteger claimedD,
                                           Map<?, ?> dMap,
                                           Map<?, ?> fMap) {
        Map<Integer, BigInteger> D = CggmpCodecUtils.decodeBigIntegerMap(dMap);
        Map<Integer, BigInteger> F = CggmpCodecUtils.decodeBigIntegerMap(fMap);
        if (!allPeersPresent(task, senderId, D, F)) {
            return false;
        }
        if (!D.containsKey(senderId)) {
            return false;
        }
        BigInteger sum = BigInteger.ZERO;
        for (int peerId : task.participants) {
            if (peerId == senderId) {
                continue;
            }
            BigInteger Dij = D.get(peerId);
            BigInteger Fij = F.get(peerId);
            if (Dij == null || Fij == null) {
                return false;
            }
            sum = sum.add(Dij).add(Fij);
        }
        sum = sum.add(claimedD);
        BigInteger nSquared = task.paillier.getPublicKeyInfo().nSquared();
        return sum.mod(nSquared).equals(BigInteger.ONE);
    }

    Map<String, Object> buildAffGEvidenceDelta(Gg20SignatureTask task, BigInteger gamma_i) {
        try {
            Map<String, Object> ev = new HashMap<>();
            Map<Integer, BigInteger> D = new HashMap<>();
            Map<Integer, BigInteger> F = new HashMap<>();
            Map<Integer, PiAffGProof> proofs = new HashMap<>();
            ECPoint Gamma = task.presignGamma.get(svc.nodeId);
            if (Gamma == null) {
                Gamma = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), gamma_i);
            }
            for (int peerId : task.participants) {
                if (peerId == svc.nodeId) {
                    continue;
                }
                BigInteger D_ji = task.presignD.get(peerId);
                BigInteger F_ji = task.presignF.get(peerId);
                if (D_ji == null || F_ji == null) {
                    return null;
                }
                D.put(peerId, D_ji);
                F.put(peerId, F_ji);
                PiAffGProof proof = PresignProofs.createAffGProofNegY(
                        Secp256k1CurveUtils.G(),
                        Gamma,
                        task.peerPaillierKeys.get(peerId).n(),
                        task.paillier.getPublicKeyInfo().n(),
                        task.presignK.get(peerId),
                        D_ji,
                        F_ji,
                        gamma_i,
                        task.presignBeta.get(peerId),
                        task.presignRho.get(peerId),
                        task.presignMu.get(peerId),
                        svc.proofKappa,
                        svc.proofEpsBits,
                        CggmpProtocolUtils.buildPresignContext(task.taskId, svc.nodeId, "R2")
                );
                proofs.put(peerId, proof);
            }
            ev.put("affGProofs", CggmpSignaturePresignHandler.encodeAffGProofMap(proofs));
            ev.put("D_map", CggmpCodecUtils.encodeBigIntegerMap(D));
            ev.put("F_map", CggmpCodecUtils.encodeBigIntegerMap(F));
            return ev;
        } catch (Exception e) {
            logger.warn("Failed to build AffG delta evidence: {}", e.getMessage());
            return null;
        }
    }

    Map<String, Object> buildAffGEvidenceChi(Gg20SignatureTask task, BigInteger x_i) {
        try {
            Map<String, Object> ev = new HashMap<>();
            Map<Integer, BigInteger> D = new HashMap<>();
            Map<Integer, BigInteger> F = new HashMap<>();
            Map<Integer, PiAffGProof> proofs = new HashMap<>();
            ECPoint X_i = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), x_i);
            for (int peerId : task.participants) {
                if (peerId == svc.nodeId) {
                    continue;
                }
                BigInteger D_ji = task.presignDhat.get(peerId);
                BigInteger F_ji = task.presignFhat.get(peerId);
                if (D_ji == null || F_ji == null) {
                    return null;
                }
                D.put(peerId, D_ji);
                F.put(peerId, F_ji);
                PiAffGProof proof = PresignProofs.createAffGProofNegY(
                        Secp256k1CurveUtils.G(),
                        X_i,
                        task.peerPaillierKeys.get(peerId).n(),
                        task.paillier.getPublicKeyInfo().n(),
                        task.presignK.get(peerId),
                        D_ji,
                        F_ji,
                        x_i,
                        task.presignBetaHat.get(peerId),
                        task.presignRhoHat.get(peerId),
                        task.presignMuHat.get(peerId),
                        svc.proofKappa,
                        svc.proofEpsBits,
                        CggmpProtocolUtils.buildPresignContext(task.taskId, svc.nodeId, "R2H")
                );
                proofs.put(peerId, proof);
            }
            ev.put("affGProofsHat", CggmpSignaturePresignHandler.encodeAffGProofMap(proofs));
            ev.put("Dhat_map", CggmpCodecUtils.encodeBigIntegerMap(D));
            ev.put("Fhat_map", CggmpCodecUtils.encodeBigIntegerMap(F));
            return ev;
        } catch (Exception e) {
            logger.warn("Failed to build AffG chi evidence: {}", e.getMessage());
            return null;
        }
    }

    boolean verifyAffGEvidence(Gg20SignatureTask task, int senderId, Map<?, ?> evidence) {
        try {
            Map<?, ?> proofs = (Map<?, ?>) evidence.get("affGProofs");
            Map<?, ?> proofsHat = (Map<?, ?>) evidence.get("affGProofsHat");
            if (proofs == null && proofsHat == null) {
                return true;
            }
            if (proofs != null) {
                Map<?, ?> dMap = (Map<?, ?>) evidence.get("D_map");
                Map<?, ?> fMap = (Map<?, ?>) evidence.get("F_map");
                if (dMap == null || fMap == null) {
                    return false;
                }
                Map<Integer, BigInteger> D = CggmpCodecUtils.decodeBigIntegerMap(dMap);
                Map<Integer, BigInteger> F = CggmpCodecUtils.decodeBigIntegerMap(fMap);
                if (allPeersPresent(task, senderId, proofs, D, F)) {
                    return false;
                }
                for (Map.Entry<Integer, BigInteger> e : D.entrySet()) {
                    int peerId = e.getKey();
                    if (peerId == senderId) {
                        continue;
                    }
                    PiAffGProof proof = CggmpCodecUtils.decodePiAffGProof((Map<?, ?>) proofs.get(peerId));
                    BigInteger K_peer = task.presignK.get(peerId);
                    PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(peerId);
                    ECPoint Gamma = task.presignGamma.get(senderId);
                    if (Gamma == null || K_peer == null || pk == null) {
                        return false;
                    }
                    if (!PresignProofs.verifyAffGProof(proof,
                            Secp256k1CurveUtils.G(),
                            Gamma,
                            pk.n(),
                            task.paillier.getPublicKeyInfo().n(),
                            K_peer,
                            e.getValue(),
                            F.get(peerId),
                            svc.proofKappa,
                            svc.proofEpsBits,
                            CggmpProtocolUtils.buildPresignContext(task.taskId, senderId, "R2"))) {
                        return false;
                    }
                }
            }
            if (proofsHat != null) {
                Map<?, ?> dMap = (Map<?, ?>) evidence.get("Dhat_map");
                Map<?, ?> fMap = (Map<?, ?>) evidence.get("Fhat_map");
                if (dMap == null || fMap == null) {
                    return false;
                }
                Map<Integer, BigInteger> D = CggmpCodecUtils.decodeBigIntegerMap(dMap);
                Map<Integer, BigInteger> F = CggmpCodecUtils.decodeBigIntegerMap(fMap);
                if (allPeersPresent(task, senderId, proofsHat, D, F)) {
                    return false;
                }
                for (Map.Entry<Integer, BigInteger> e : D.entrySet()) {
                    int peerId = e.getKey();
                    if (peerId == senderId) {
                        continue;
                    }
                    PiAffGProof proof = CggmpCodecUtils.decodePiAffGProof((Map<?, ?>) proofsHat.get(peerId));
                    BigInteger K_peer = task.presignK.get(peerId);
                    PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(peerId);
                    ECPoint X = task.presignSTilde.get(senderId);
                    if (X == null || K_peer == null || pk == null) {
                        return false;
                    }
                    if (!PresignProofs.verifyAffGProof(proof,
                            Secp256k1CurveUtils.G(),
                            X,
                            pk.n(),
                            task.paillier.getPublicKeyInfo().n(),
                            K_peer,
                            e.getValue(),
                            F.get(peerId),
                            svc.proofKappa,
                            svc.proofEpsBits,
                            CggmpProtocolUtils.buildPresignContext(task.taskId, senderId, "R2H"))) {
                        return false;
                    }
                }
            }
            return true;
        } catch (Exception e) {
            logger.warn("Failed to verify AffG evidence: {}", e.getMessage());
            return false;
        }
    }

    boolean allPeersPresent(Gg20SignatureTask task,
                            int senderId,
                            Map<?, ?> proofs,
                            Map<?, ?> dMap,
                            Map<?, ?> fMap) {
        for (int peerId : task.participants) {
            if (peerId == senderId) {
                continue;
            }
            if (!proofs.containsKey(peerId) || !dMap.containsKey(peerId) || !fMap.containsKey(peerId)) {
                return true;
            }
        }
        return false;
    }

    boolean allPeersPresent(Gg20SignatureTask task,
                            int senderId,
                            Map<?, ?> dMap,
                            Map<?, ?> fMap) {
        for (int peerId : task.participants) {
            if (peerId == senderId) {
                continue;
            }
            if (!dMap.containsKey(peerId) || !fMap.containsKey(peerId)) {
                return false;
            }
        }
        return true;
    }

    private BigInteger computePresignDForSelf(Gg20SignatureTask task,
                                              Map<Integer, BigInteger> incomingD,
                                              Map<Integer, BigInteger> outgoingF) {
        BigInteger nSquared = task.paillier.getPublicKeyInfo().nSquared();
        BigInteger acc = BigInteger.ONE;
        for (int peerId : task.participants) {
            if (peerId == svc.nodeId) {
                continue;
            }
            BigInteger d = incomingD.get(peerId);
            BigInteger f = outgoingF.get(peerId);
            if (d == null || f == null) {
                return null;
            }
            acc = acc.multiply(d).mod(nSquared);
            acc = acc.multiply(f).mod(nSquared);
        }
        return acc;
    }

    void attemptExcludeAndRestart(Gg20SignatureTask task, int offenderId, String reason) {
        if (!task.participants.contains(offenderId)) {
            svc.failSignatureTask(task, "Complaint (offender not participant): " + reason);
            return;
        }
        int required = Math.min(Math.max(1, task.threshold), task.nodesCount);
        LinkedHashSet<Integer> newParticipants = new LinkedHashSet<>(task.participants);
        newParticipants.remove(offenderId);
        if (newParticipants.size() < required) {
            svc.failSignatureTask(task, "Not enough participants after exclusion");
            return;
        }
        CggmpProtocolUtils.fireAndForget(broadcastExclude(task, offenderId), logger, "CGGMP_SIGN_EXCLUDE");
        svc.failSignatureTask(task, "Excluded offender " + offenderId + ", restarting");

        String newTaskId = task.taskId + "-excl-" + offenderId + "-" + System.currentTimeMillis();
        svc.createSignatureTaskWithIdAndGroupKey(newTaskId, task.groupPublicKey, task.message, task.initiatorId, newParticipants);
        Gg20SignatureTask newTask = svc.signatureTasks.get(newTaskId);
        if (newTask == null) {
            return;
        }
        svc.offlineHandler.initSignatureContext(newTask);
        newTask.start();
        CggmpProtocolUtils.fireAndForget(svc.offlineHandler.broadcastOfflineInit(newTask), logger, "CGGMP_SIGN_OFFLINE_INIT");
        svc.offlineHandler.runOfflinePhase(newTask).exceptionally(ex -> {
            logger.error("Failed offline phase for restarted task {}: {}", newTaskId, ex.getMessage());
            return null;
        });
    }

    private CompletableFuture<Void> broadcastExclude(Gg20SignatureTask task, int offenderId) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", svc.nodeId);
        data.put("offenderId", offenderId);
        return svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_SIGN_EXCLUDE, data));
    }
}
