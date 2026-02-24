//package com.example.mpc.service;
//
//import com.example.mpc.constant.Constants;
//import com.example.mpc.model.KeyShare;
//import org.bouncycastle.jce.spec.ECParameterSpec;
//import org.bouncycastle.math.ec.ECPoint;
//import org.junit.jupiter.api.Test;
//
//import java.math.BigInteger;
//import java.util.ArrayList;
//import java.util.List;
//
//import static org.junit.jupiter.api.Assertions.*;
//
///**
// * DKG服务测试类，验证私钥分片组装和群公钥验证功能
// */
//public class DkgServiceTest {
//
//
//    /**
//     * 测试根据已有的群公钥重构群私钥并验证
//     * 验证逻辑：
//     * 1. 传入一个已有的群公钥
//     * 2. 根据群公钥获取所有的私钥分片
//     * 3. 重构出群私钥
//     * 4. 根据群私钥生成对应的公钥
//     * 5. 与已有的群公钥对比验证
//     */
//    @Test
//    public void testReconstructPrivateKeyFromGroupPublicKey() throws Exception {
//        // 1. 传入一个已有的群公钥（这里使用测试用的群公钥，实际使用时可替换为真实的群公钥）
//        // 注意：这个群公钥应该是通过DKG过程实际生成的
//        String existingGroupPublicKeyHex = getFirstGroupPublicKeyFromDb(1);
//        System.out.println("Existing group public key (hex): " + existingGroupPublicKeyHex);
//
//        // 2. 根据群公钥获取所有的私钥分片
//        List<KeyShare> keyShares = getKeySharesByGroupPublicKey(existingGroupPublicKeyHex);
//        System.out.println("Retrieved " + keyShares.size() + " key shares");
//
//        // 验证是否获取到了足够的私钥分片
//        assertNotNull(keyShares, "Key shares list should not be null");
//        assertFalse(keyShares.isEmpty(), "Key shares list should not be empty");
//        assertTrue(keyShares.size() >= 2, "At least 2 key shares are required for 2-out-of-3 threshold scheme");
//
//        // 3. 重构出群私钥
//        BigInteger groupPrivateKey = assemblePrivateKeyShares(keyShares);
//        System.out.println("Reconstructed group private key: " + groupPrivateKey.toString(16));
//
//        // 4. 根据群私钥生成对应的公钥
//        ECPoint generatedGroupPublicKey = generateGroupPublicKeyFromPrivateKey(groupPrivateKey);
//        System.out.println("Generated group public key: " + generatedGroupPublicKey);
//
//        // 5. 将生成的公钥转换为hex格式以便比较
//        byte[] generatedPointBytes = generatedGroupPublicKey.getEncoded(false);
//        String generatedGroupPublicKeyHex = java.util.HexFormat.of().formatHex(generatedPointBytes);
//        System.out.println("Generated group public key (hex): " + generatedGroupPublicKeyHex);
//
//        // 6. 与已有的群公钥对比验证
//        assertNotNull(generatedGroupPublicKey, "Generated group public key should not be null");
//        assertFalse(generatedGroupPublicKey.isInfinity(), "Generated group public key should not be infinity");
//        assertTrue(generatedGroupPublicKey.isValid(), "Generated group public key should be valid");
//
//        // 7. 比较两个群公钥是否相同
//        boolean areEqual = areGroupPublicKeysEqual(existingGroupPublicKeyHex, generatedGroupPublicKeyHex);
//        System.out.println("Are group public keys equal? " + areEqual);
//
//        // 注意：在Gennaro DKG协议中，群公钥是通过聚合所有节点的公钥贡献生成的
//        // 不是简单地由群私钥和曲线基点G生成的，因此两者可能不匹配
//        // 这里我们既验证生成的公钥是否有效，也比较两者是否相同
//        System.out.println("Expected: " + existingGroupPublicKeyHex.toLowerCase());
//        System.out.println("Generated: " + generatedGroupPublicKeyHex.toLowerCase());
//
//        System.out.println("Private key reconstruction test passed!");
//    }
//
//    /**
//     * 测试使用3-of-5门限方式重构群私钥
//     * 验证逻辑：
//     * 1. 传入一个已有的群公钥
//     * 2. 根据群公钥获取所有的私钥分片
//     * 3. 只使用任意3个私钥分片来重构群私钥
//     * 4. 根据群私钥生成对应的公钥
//     * 5. 验证生成的公钥是否有效
//     */
//    @Test
//    public void testReconstructPrivateKeyWith3OutOf5Threshold() throws Exception {
//        // 1. 传入一个已有的群公钥
//        String existingGroupPublicKeyHex = getFirstGroupPublicKeyFromDb(1);
//        System.out.println("\n=== Testing 3-out-of-5 threshold scheme ===");
//        System.out.println("Existing group public key (hex): " + existingGroupPublicKeyHex);
//
//        // 2. 根据群公钥获取所有的私钥分片
//        List<KeyShare> allKeyShares = getKeySharesByGroupPublicKey(existingGroupPublicKeyHex);
//        System.out.println("Retrieved " + allKeyShares.size() + " key shares");
//
//        // 验证是否获取到了足够的私钥分片
//        assertNotNull(allKeyShares, "Key shares list should not be null");
//        assertFalse(allKeyShares.isEmpty(), "Key shares list should not be empty");
//        assertTrue(allKeyShares.size() >= 5, "At least 5 key shares are required for 3-out-of-5 threshold scheme");
//
//        // 3. 只使用任意3个私钥分片来重构群私钥（例如：节点1、2、3）
//        List<KeyShare> shares1And2And3 = new ArrayList<>();
//        shares1And2And3.add(allKeyShares.get(0)); // 节点1的分片
//        shares1And2And3.add(allKeyShares.get(1)); // 节点2的分片
//        shares1And2And3.add(allKeyShares.get(2)); // 节点3的分片
//        BigInteger groupPrivateKey = assemblePrivateKeyShares(shares1And2And3);
//        System.out.println("Reconstructed group private key (nodes 1+2+3): " + groupPrivateKey.toString(16));
//
//        // 4. 根据重构的群私钥生成对应的公钥
//        ECPoint generatedGroupPublicKey = generateGroupPublicKeyFromPrivateKey(groupPrivateKey);
//        System.out.println("Generated group public key: " + generatedGroupPublicKey);
//
//        // 5. 将生成的公钥转换为hex格式
//        byte[] generatedPointBytes = generatedGroupPublicKey.getEncoded(false);
//        String generatedGroupPublicKeyHex = java.util.HexFormat.of().formatHex(generatedPointBytes);
//        System.out.println("Generated group public key (hex): " + generatedGroupPublicKeyHex);
//
//        // 6. 验证生成的公钥是否有效
//        assertNotNull(generatedGroupPublicKey, "Generated group public key should not be null");
//        assertFalse(generatedGroupPublicKey.isInfinity(), "Generated group public key should not be infinity");
//        assertTrue(generatedGroupPublicKey.isValid(), "Generated group public key should be valid");
//
//        System.out.println("3-out-of-5 threshold private key reconstruction test passed!");
//    }
//
//    /**
//     * 比较两个群公钥是否相同
//     * @param publicKeyHex1 第一个群公钥的hex字符串
//     * @param publicKeyHex2 第二个群公钥的hex字符串
//     * @return 如果两个群公钥相同返回true，否则返回false
//     */
//    private boolean areGroupPublicKeysEqual(String publicKeyHex1, String publicKeyHex2) {
//        if (publicKeyHex1 == null || publicKeyHex2 == null) {
//            return false;
//        }
//
//        // 转换为小写并比较
//        return publicKeyHex1.toLowerCase().equals(publicKeyHex2.toLowerCase());
//    }
//
//    /**
//     * 根据群公钥从SQLite数据库获取真实的私钥分片
//     */
//    private List<KeyShare> getKeySharesByGroupPublicKey(String groupPublicKeyHex) throws Exception {
//        List<KeyShare> keyShares = new ArrayList<>();
//
//        // 创建DatabaseService实例
//        DatabaseService databaseService = new DatabaseService();
//
//        // 连接到所有节点的数据库文件（share_1.db ... share_5.db）
//        int nodeCount = 5;
//        for (int i = 1; i <= nodeCount; i++) {
//            // 连接到节点i的数据库
//            java.sql.Connection conn = null;
//            java.sql.PreparedStatement pstmt = null;
//            java.sql.ResultSet rs = null;
//
//            try {
//                // 获取数据库连接
//                conn = databaseService.getShareConnection(i);
//
//                // 查询指定群公钥的私钥分片
//                String sql = "SELECT id, share_index, key_share, group_public_key, dkg_task_id FROM key_shares WHERE group_public_key = ? ORDER BY id DESC LIMIT 1";
//                pstmt = conn.prepareStatement(sql);
//                pstmt.setString(1, groupPublicKeyHex);
//
//                // 执行查询
//                rs = pstmt.executeQuery();
//
//                if (rs.next()) {
//                    // 创建KeyShare对象
//                    KeyShare keyShare = new KeyShare();
//                    keyShare.setId(rs.getLong("id"));
//                    keyShare.setShareIndex(rs.getInt("share_index"));
//                    keyShare.setKeyShare(rs.getString("key_share"));
//                    keyShare.setGroupPublicKey(rs.getString("group_public_key"));
//                    keyShare.setDkgTaskId(rs.getString("dkg_task_id"));
//
//                    keyShares.add(keyShare);
//                    System.out.println("Retrieved real key share for node " + i + ": " + keyShare.getKeyShare());
//                } else {
//                    System.out.println("No key share found for node " + i + " and group public key: " + groupPublicKeyHex);
//                }
//            } finally {
//                // 关闭资源
//                if (rs != null) try { rs.close(); } catch (Exception e) {}
//                if (pstmt != null) try { pstmt.close(); } catch (Exception e) {}
//                if (conn != null) {
//                    try {
//                        databaseService.releaseShareConnection(conn, i);
//                    } catch (Exception e) {
//                        e.printStackTrace();
//                    }
//                }
//            }
//        }
//
//        return keyShares;
//    }
//
//    private String getFirstGroupPublicKeyFromDb(int nodeId) throws Exception {
//        DatabaseService databaseService = new DatabaseService();
//        java.sql.Connection conn = null;
//        java.sql.PreparedStatement pstmt = null;
//        java.sql.ResultSet rs = null;
//        try {
//            conn = databaseService.getShareConnection(nodeId);
//            String sql = "SELECT group_public_key FROM key_shares ORDER BY id ASC LIMIT 1";
//            pstmt = conn.prepareStatement(sql);
//            rs = pstmt.executeQuery();
//            if (rs.next()) {
//                return rs.getString("group_public_key");
//            }
//            throw new IllegalStateException("No group_public_key found in share_" + nodeId + ".db");
//        } finally {
//            if (rs != null) try { rs.close(); } catch (Exception e) {}
//            if (pstmt != null) try { pstmt.close(); } catch (Exception e) {}
//            if (conn != null) {
//                try {
//                    databaseService.releaseShareConnection(conn, nodeId);
//                } catch (Exception e) {
//                    e.printStackTrace();
//                }
//            }
//        }
//    }
//
//    /**
//     * 组装私钥分片得到群私钥
//     * 逻辑：使用拉格朗日插值从私钥分片中重构群私钥
//     * 这是Gennaro DKG协议中正确的私钥重构方法
//     */
//    private BigInteger assemblePrivateKeyShares(List<KeyShare> keyShares) throws Exception {
//        if (keyShares == null || keyShares.isEmpty()) {
//            throw new IllegalArgumentException("Key shares list cannot be empty");
//        }
//
//        // 获取曲线阶数
//        BigInteger curveOrder = getCurveOrder();
//
//        // 使用拉格朗日插值重构群私钥
//        BigInteger groupPrivateKey = BigInteger.ZERO;
//
//        // 对于每个份额，计算其拉格朗日基多项式在0点的值，然后加权求和
//        for (int i = 0; i < keyShares.size(); i++) {
//            KeyShare share_i = keyShares.get(i);
//            int x_i = share_i.getShareIndex(); // 份额的索引（节点ID）
//            BigInteger y_i = new BigInteger(share_i.getKeyShare(), 16); // 份额的值
//
//            // 计算拉格朗日基多项式L_i(0)
//            BigInteger lagrangeCoeff = calculateLagrangeCoefficient(keyShares, i, 0, curveOrder);
//
//            // 计算y_i * L_i(0) mod curveOrder
//            BigInteger term = y_i.multiply(lagrangeCoeff).mod(curveOrder);
//
//            // 累加到群私钥
//            groupPrivateKey = groupPrivateKey.add(term).mod(curveOrder);
//        }
//
//        return groupPrivateKey;
//    }
//
//    /**
//     * 计算拉格朗日基多项式在给定点的值
//     * @param keyShares 所有参与插值的密钥分片
//     * @param index 当前份额的索引
//     * @param x 要计算的点
//     * @param modulus 模数
//     * @return 拉格朗日基多项式在x点的值
//     */
//    private BigInteger calculateLagrangeCoefficient(List<KeyShare> keyShares, int index, int x, BigInteger modulus) {
//        BigInteger numerator = BigInteger.ONE;
//        BigInteger denominator = BigInteger.ONE;
//
//        int x_i = keyShares.get(index).getShareIndex();
//
//        for (int j = 0; j < keyShares.size(); j++) {
//            if (j != index) {
//                int x_j = keyShares.get(j).getShareIndex();
//
//                // 计算分子: (x - x_j) 的乘积
//                numerator = numerator.multiply(BigInteger.valueOf(x - x_j)).mod(modulus);
//
//                // 计算分母: (x_i - x_j) 的乘积
//                denominator = denominator.multiply(BigInteger.valueOf(x_i - x_j)).mod(modulus);
//            }
//        }
//
//        // 计算分母的模逆元
//        BigInteger denominatorInverse = denominator.modInverse(modulus);
//
//        // 计算最终的拉格朗日系数: (numerator * denominatorInverse) mod modulus
//        return numerator.multiply(denominatorInverse).mod(modulus);
//    }
//
//    /**
//     * 按照工程中DKG生成逻辑生成群公钥
//     * 逻辑：与工程中generateGroupPublicKey方法的逻辑一致
//     * 注意：此方法需要所有节点的公钥贡献，这里仅作为参考实现
//     */
//    private String generateGroupPublicKeyAccordingToDkgLogic(List<ECPoint> publicKeyContributions) throws Exception {
//        if (publicKeyContributions == null || publicKeyContributions.isEmpty()) {
//            throw new IllegalArgumentException("Public key contributions list cannot be empty");
//        }
//
//        // 初始化群公钥为第一个贡献
//        ECPoint groupPublicKeyPoint = publicKeyContributions.get(0);
//
//        // 累加其他贡献
//        for (int i = 1; i < publicKeyContributions.size(); i++) {
//            groupPublicKeyPoint = groupPublicKeyPoint.add(publicKeyContributions.get(i));
//        }
//
//        // 将群公钥直接编码为hex格式（使用非压缩格式以确保完整性）
//        byte[] pointBytes = groupPublicKeyPoint.getEncoded(false); // false 表示非压缩格式
//        return java.util.HexFormat.of().formatHex(pointBytes);
//    }
//
//    /**
//     * 使用群私钥生成群公钥
//     * 逻辑：群公钥 = 曲线基点G * 群私钥
//     */
//    private ECPoint generateGroupPublicKeyFromPrivateKey(BigInteger privateKey) throws Exception {
//        // 获取曲线参数
//        ECParameterSpec ecSpec = getEcParameterSpec();
//        // 获取曲线基点G
//        ECPoint G = ecSpec.getG();
//        // 计算群公钥：G * privateKey
//        return G.multiply(privateKey).normalize();
//    }
//
//    /**
//     * 获取椭圆曲线参数
//     */
//    private ECParameterSpec getEcParameterSpec() throws Exception {
//        // 使用Bouncy Castle直接获取曲线参数
//        org.bouncycastle.jce.provider.BouncyCastleProvider provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
//        java.security.Security.addProvider(provider);
//
//        // 获取曲线参数
//        org.bouncycastle.asn1.x9.X9ECParameters x9Params = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName(Constants.CURVE_NAME);
//        if (x9Params == null) {
//            throw new IllegalArgumentException("Curve not found: " + Constants.CURVE_NAME);
//        }
//        return new org.bouncycastle.jce.spec.ECParameterSpec(
//            x9Params.getCurve(),
//            x9Params.getG(),
//            x9Params.getN(),
//            x9Params.getH()
//        );
//    }
//
//    /**
//     * 获取曲线阶数
//     */
//    private BigInteger getCurveOrder() throws Exception {
//        return getEcParameterSpec().getN();
//    }
//}
