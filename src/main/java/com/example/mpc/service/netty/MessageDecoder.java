package com.example.mpc.service.netty;

import com.example.mpc.service.NodeService;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

/**
 * 消息解码器
 */
public class MessageDecoder extends LengthFieldBasedFrameDecoder {
    public MessageDecoder() {
        super(1024 * 1024, 0, 4, 0, 4);
    }

    @Override
    protected Object decode(ChannelHandlerContext ctx, ByteBuf in) throws Exception {
        ByteBuf frame = (ByteBuf) super.decode(ctx, in);
        if (frame == null) {
            return null;
        }

        byte[] data = new byte[frame.readableBytes()];
        frame.readBytes(data);
        frame.release();

        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return ois.readObject();
        }
    }
}
