package com.example.mpc.service.netty;

import com.example.mpc.service.NodeService;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;

/**
 * 消息编码器
 */
public class MessageEncoder extends MessageToByteEncoder<NodeService.Message> {
    @Override
    protected void encode(ChannelHandlerContext ctx, NodeService.Message msg, ByteBuf out) throws Exception {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(msg);
            oos.flush();
            byte[] data = baos.toByteArray();
            
            // 写入长度前缀
            out.writeInt(data.length);
            // 写入数据
            out.writeBytes(data);
        }
    }
}
