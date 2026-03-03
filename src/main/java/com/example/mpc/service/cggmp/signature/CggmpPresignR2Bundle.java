package com.example.mpc.service.cggmp.signature;

import com.example.mpc.service.cggmp.types.BigIntIndexMap;

public record CggmpPresignR2Bundle(
        CggmpPresignR2Context ctx,
        BigIntIndexMap D,
        BigIntIndexMap Dhat,
        BigIntIndexMap F,
        BigIntIndexMap Fhat) {
}
