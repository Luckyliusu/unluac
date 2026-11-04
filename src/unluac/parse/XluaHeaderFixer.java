package unluac.parse;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * xLua 定制 dump 头 → 标准 Lua 5.3 头的原地转换器。
 *
 * xLua 布局 (据逆向 xlua.dll checkHeader sub_18002E460 + loadString sub_18002D9A0):
 *   sig(4) ver(1) fmt(1) LUAC_DATA(6)
 *   sizeof(int)=4, sizeof(Instruction)=4, sizeof(lua_Integer)=8, sizeof(lua_Number)=8  [4 字节, 无 size_t]
 *   [1 个额外字节: 0xFF (loadString 的"扩展标记"占位/或其它, 观察值为 08/FF 不定 — 实为 int_test 前的 1 字节)]
 *   int_test(8) float_test(8)
 *   [1 字节: 主 chunk upvalue 数]
 *   main proto
 *
 *   string 编码: 1 字节长度 (0xFF → 跟 4 字节 LE 扩展), 长度 = size-1
 *
 * 标准 5.3 (unluac 期望):
 *   sig(4) ver(1) fmt(1) LUAC_DATA(6)
 *   sizeof(int)=4, sizeof(size_t)=4, sizeof(Instruction)=4, integ=8, num=8
 *   int_test(8) float_test(8)
 *   [1 字节 upvalue 数]
 *   main proto
 *
 * 转换 = 在 int 字节后插入 size_t 字节(值=4), 并删除 int_test 前的额外字节。
 * 转换后 buffer 的 sizeT 宽度 = 4, 与 xlua 的 0xFF 扩展格式(loadBlock 4B)匹配,
 * 且 LStringType53 的 1B 长度读取直接兼容 → 无需改 unluac 其它任何代码。
 */
public final class XluaHeaderFixer {

  private static final byte[] LUAC_DATA = {
    0x19, (byte) 0x93, 0x0D, 0x0A, 0x1A, 0x0A
  };

  private static boolean lastWasXlua = false;

  private XluaHeaderFixer() {}

  /** 上一次 fix() 是否检测到了 xLua 定制头 (供 BHeader 查询)。 */
  public static boolean wasXlua() {
    return lastWasXlua;
  }

  /**
   * 检测并原地转换 xLua 定制头。
   * @return 若输入是 xLua 定制 dump 则返回修复后的新 buffer; 否则返回原 buffer(标准文件或非 Lua 文件)。
   */
  public static ByteBuffer fix(ByteBuffer in) {
    return fix(in, null);
  }

  public static ByteBuffer fix(ByteBuffer in, boolean[] flagOut) {
    lastWasXlua = false;
    if (flagOut != null) flagOut[0] = false;
    if (in.remaining() < 34) {
      return in;
    }
    in.mark();
    byte[] sig = new byte[4];
    in.get(sig);
    if (sig[0] != 0x1B || sig[1] != 'L' || sig[2] != 'u' || sig[3] != 'a') {
      in.reset();
      return in;
    }
    byte ver = in.get();          // 0x53
    byte fmt = in.get();
    byte[] data = new byte[6];
    in.get(data);
    if (ver != 0x53 || !java.util.Arrays.equals(data, LUAC_DATA)) {
      in.reset();
      return in;
    }
    if (flagOut != null && fmt == 1) flagOut[0] = true;
    // 4 个 size 字节: xlua 期望 int=4, instr=4, integ=8, num=8
    int szInt = in.get() & 0xFF;
    int szInstr = in.get() & 0xFF;
    int szInteg = in.get() & 0xFF;
    int szNum = in.get() & 0xFF;
    if (!(szInt == 4 && szInstr == 4 && szInteg == 8 && szNum == 8)) {
      // 变体检测: 已是标准 5.3 头布局 (int=4 size_t=8 instr=4 integ=8 num=8)
      // 但 int_test 前多 1 个字节 (某些处理工具产生)
      int x5 = in.get() & 0xFF;      // @16 = num size (5th byte of standard header)
      int x6 = in.get() & 0xFF;      // @17 = extra byte
      if (szInt == 4 && szInstr == 8 && szInteg == 4 && szNum == 8 && x5 == 8 && x6 == 8) {
        // @12-17: 04 08 04 08 08 08; int_test 应在 @18
        int b0 = in.get() & 0xFF;
        int b1 = in.get() & 0xFF;
        if (b0 == 0x78 && b1 == 0x56) {
          // 确认: 删除 @17 的额外字节即可
          in.reset();
          lastWasXlua = true;
          if (flagOut != null) flagOut[0] = true;
          byte[] head = new byte[17];   // 0-16 (标准头, 不含额外字节)
          in.position(0);
          in.get(head);
          in.position(18);              // 跳过 0-17 (含额外字节)
          byte[] rest = new byte[in.remaining()];
          in.get(rest);
          ByteBuffer out = ByteBuffer.allocate(head.length + rest.length);
          out.order(ByteOrder.LITTLE_ENDIAN);
          out.put(head);
          out.put(rest);
          out.flip();
          return out;
        }
      }
      in.reset();
      return in;
    }
    // int_test(0x5678 LE) 可能紧跟 sizes(原始 dump) 或隔 1 个额外字节(某些处理过的文件)
    int p16 = in.get() & 0xFF;
    int p17 = in.get() & 0xFF;
    int extraPos;      // 额外字节的位置, 无则 -1
    if (p16 == 0x78 && p17 == 0x56) {
      extraPos = -1;   // 无额外字节: sizes 后直接 int_test
    } else {
      // p16 是额外字节, int_test 从下一字节开始
      int b0 = p17;
      int b1 = in.get() & 0xFF;
      if (!(b0 == 0x78 && b1 == 0x56)) {
        in.reset();
        return in;
      }
      extraPos = 16;
    }
    in.reset();
    lastWasXlua = true;
    if (flagOut != null) flagOut[0] = true;

    // 构造标准 5.3 头
    int copyFrom = (extraPos == -1) ? 16 : 17;  // int_test 起始
    byte[] rest = new byte[in.remaining() - copyFrom];
    in.position(copyFrom);
    in.get(rest);

    ByteBuffer out = ByteBuffer.allocate(rest.length + 17 + 1);
    out.order(ByteOrder.LITTLE_ENDIAN);
    out.put(sig);
    out.put(ver);
    out.put(fmt);
    out.put(LUAC_DATA);
    out.put((byte) 4);  // sizeof(int)
    out.put((byte) 4);  // sizeof(size_t)  ← 新插入, 与 xlua 0xFF 扩展宽度(loadBlock 4B)一致
    out.put((byte) 4);  // sizeof(Instruction)
    out.put((byte) 8);  // sizeof(lua_Integer)
    out.put((byte) 8);  // sizeof(lua_Number)
    out.put(rest);
    out.flip();
    return out;
  }
}
