package utils.veriDnsHeader;

import utils.Commons;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class VeriDNSHeader {
    private Type type;

    private int length;

    private int sequenceNumber;

    public VeriDNSHeader(int type, int length, int sequenceNumber) {
        this.type = new Type(type);
        this.length = length;
        this.sequenceNumber = sequenceNumber;
    }

    public Type getType() {
        return this.type;
    }

    public int getTypeValue() {
        return this.type.getValue();
    }

    public int getLength() {
        return this.length;
    }

    public int getBodyLength() {
        return this.length - Commons.Length.HEADER_TOTAL;
    }

    public int getSequenceNumber() {
        return this.sequenceNumber;
    }

    public byte[] getRawData() {
        ByteBuffer dataBuffer = ByteBuffer.allocate(Commons.Length.HEADER_TOTAL);
        dataBuffer.clear();

        dataBuffer.putInt(this.type.getValue());
        dataBuffer.putInt(this.length);
        dataBuffer.putInt(this.sequenceNumber);

        byte[] rawData = new byte[dataBuffer.position()];
        dataBuffer.flip();
        dataBuffer.get(rawData);

        return rawData;
    }

    public static VeriDNSHeader parse(InputStream inputStream) throws IOException {
        // read the header
        byte[] headerRawData = new byte[Commons.Length.HEADER_TOTAL];
        inputStream.read(headerRawData);

        // get the type
        byte[] typeRawData = new byte[Commons.Length.TYPE];
        System.arraycopy(headerRawData, 0, typeRawData, 0, Commons.Length.TYPE);
        int type = ByteBuffer.wrap(typeRawData).getInt();

        // get the body length
        byte[] lengthRawData = new byte[Commons.Length.LENGTH];
        System.arraycopy(headerRawData, Commons.Length.TYPE, lengthRawData, 0, Commons.Length.LENGTH);
        int length = ByteBuffer.wrap(lengthRawData).getInt();

        // get the sequence number
        byte[] sequenceNumberRawData = new byte[Commons.Length.SEQUENCE_NUMBER];
        System.arraycopy(headerRawData, Commons.Length.TYPE + Commons.Length.LENGTH,
                sequenceNumberRawData, 0, Commons.Length.SEQUENCE_NUMBER);
        int sequenceNumber = ByteBuffer.wrap(sequenceNumberRawData).getInt();

        return new VeriDNSHeader(type, length, sequenceNumber);
    }

    public boolean isSeqCorrect(int expectedSeq){
        if (this.sequenceNumber == expectedSeq)
            return true;
        else
        {
            System.err.println("Message sequence number does not match. Given "
                                + this.sequenceNumber + ", expected " + expectedSeq + ".");

            return false;
        }
    }

    public boolean isTypeCorrect(Type expectedType) {
        if (this.type.isMalformed() || expectedType.isMalformed()) {
            if (this.type.isMalformed())
                System.err.println("Given message type is malformed.");
            if (expectedType.isMalformed())
                System.err.println("Expected message type is malformed.");

            return false;
        } else if (this.type.getValue() == expectedType.getValue())
            return true;
        else
        {
            System.err.println("Message type does not match. Given "
                                + this.type + ", expected " + expectedType + ".");

            return false;
        }
    }

    public boolean isLengthCorrect() {
        switch (this.type.getValue()) {
            case Type.BRANCH_SERVER_ADDR_QUERY:
                if (this.getBodyLength() != 0) {
                    System.err.println("Given message type " + this.type + ", the body should be empty.");
                    return false;
                } else {
                    return true;
                }
            case Type.BRANCH_SERVER_ADDR_ANS:
                if (this.getBodyLength() < Commons.Length.NUMBER_OF_ADDR) {
                    System.err.println("Given message type " + this.type + ", the body should be at least "
                                        + Commons.Length.NUMBER_OF_ADDR + " byte(s) long.");
                    return false;
                } else {
                    return true;
                }
            case Type.VERIDNS_REQ:
                if (this.getBodyLength() < Commons.Length.NUMBER_OF_ADDR + Commons.Length.DOMAIN_NAME) {
                    System.err.println("Given message type " + this.type + ", the body should be at least "
                            + (Commons.Length.NUMBER_OF_ADDR + Commons.Length.DOMAIN_NAME) + " byte(s) long.");
                    return false;
                } else {
                    return true;
                }
            case Type.VERIDNS_RESP:
                if (this.getBodyLength() < Commons.Length.VERIFICATION) {
                    System.err.println("Given message type " + this.type + ", the body should be at least "
                            + Commons.Length.VERIFICATION + " byte(s) long.");
                    return false;
                } else {
                    return true;
                }
            default:
                System.err.println("Message type malformed.");
                return false;
        }
    }

    public boolean isHeaderCorrect(Type expectedType, int expectedSeq) {
        if (this.isTypeCorrect(expectedType) &
            this.isSeqCorrect(expectedSeq) &
            this.isLengthCorrect()) {
            return true;
        } else {
            return false;
        }
    }
}
