//package com.example.mpc.service;
//
//import com.example.mpc.constant.Constants;
//import com.example.mpc.model.SignatureTask;
//import org.bouncycastle.jce.interfaces.ECPublicKey;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.math.ec.ECPoint;
//import org.junit.jupiter.api.Test;
//
//import java.lang.reflect.Field;
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.Security;
//import java.security.spec.ECGenParameterSpec;
//import java.util.Map;
//
//import static org.junit.jupiter.api.Assertions.assertEquals;
//import static org.junit.jupiter.api.Assertions.assertTrue;
//
//public class SignatureServiceTest {
//
//    @Test
//    public void testDuplicateCommitmentsDoNotCountdownTwice() throws Exception {
//        SignatureService service = new SignatureService();
//        String taskId = "test-task-commitment";
//        service.createSignatureTaskWithIdAndGroupKey(taskId, "00", "hello");
//
//        SignatureTask task = getSignatureTask(service, taskId);
//        long initialCount = task.commitmentsReceivedLatch.getCount();
//        assertEquals(Constants.NODES_COUNT - 1, initialCount);
//
//        ECPoint point = createTestPoint();
//
//        service.handleCommitment(2, taskId, point);
//        long afterFirst = task.commitmentsReceivedLatch.getCount();
//        assertEquals(initialCount - 1, afterFirst);
//
//        service.handleCommitment(2, taskId, point);
//        long afterSecond = task.commitmentsReceivedLatch.getCount();
//        assertEquals(afterFirst, afterSecond);
//    }
//
//    @Test
//    public void testDuplicateSignatureSharesDoNotCountdownTwice() throws Exception {
//        SignatureService service = new SignatureService();
//        String taskId = "test-task-share";
//        service.createSignatureTaskWithIdAndGroupKey(taskId, "00", "hello");
//
//        SignatureTask task = getSignatureTask(service, taskId);
//        long initialCount = task.sharesReceivedLatch.getCount();
//        assertEquals(Constants.NODES_COUNT - 1, initialCount);
//
//        service.handleSignatureShare(2, taskId, java.math.BigInteger.ONE);
//        long afterFirst = task.sharesReceivedLatch.getCount();
//        assertEquals(initialCount - 1, afterFirst);
//
//        service.handleSignatureShare(2, taskId, java.math.BigInteger.ONE);
//        long afterSecond = task.sharesReceivedLatch.getCount();
//        assertEquals(afterFirst, afterSecond);
//    }
//
//    private SignatureTask getSignatureTask(SignatureService service, String taskId) throws Exception {
//        Field field = SignatureService.class.getDeclaredField("signatureTasks");
//        field.setAccessible(true);
//        @SuppressWarnings("unchecked")
//        Map<String, SignatureTask> map = (Map<String, SignatureTask>) field.get(service);
//        SignatureTask task = map.get(taskId);
//        assertTrue(task != null, "Signature task should be created");
//        return task;
//    }
//
//    private ECPoint createTestPoint() throws Exception {
//        Security.addProvider(new BouncyCastleProvider());
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
//        ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
//        keyGen.initialize(ecSpec);
//        KeyPair keyPair = keyGen.generateKeyPair();
//        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
//        return publicKey.getParameters().getG().multiply(java.math.BigInteger.ONE);
//    }
//}
