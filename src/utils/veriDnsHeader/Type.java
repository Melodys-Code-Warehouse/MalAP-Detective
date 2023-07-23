package utils.veriDnsHeader;

public class Type {
    public static final int BRANCH_SERVER_ADDR_QUERY = 0;

    public static final int BRANCH_SERVER_ADDR_ANS = 1;

    public static final int VERIDNS_REQ = 2;

    public static final int VERIDNS_RESP = 3;

    public static final int MALFORMED_TYPE = -1;

    private int value;

    public Type(int value) {
        if (value == BRANCH_SERVER_ADDR_QUERY ||
                value == BRANCH_SERVER_ADDR_ANS ||
                value == VERIDNS_REQ ||
                value == VERIDNS_RESP) {
            this.value = value;
        }
        else {
            this.value = MALFORMED_TYPE;
        }
    }

    public int getValue() {
        return this.value;
    }

    @Override
    public String toString() {
        switch (value) {
            case BRANCH_SERVER_ADDR_QUERY:
                return "BRANCH_SERVER_ADDR_QUERY";
            case BRANCH_SERVER_ADDR_ANS:
                return "BRANCH_SERVER_ADDR_ANS";
            case VERIDNS_REQ:
                return "VERIDNS_REQ";
            case VERIDNS_RESP:
                return "VERIDNS_RESP";
            default:
                return "MALFORMED_TYPE";
        }
    }

    public boolean isMalformed() {
        if (this.value == MALFORMED_TYPE) {
            return true;
        } else {
            return false;
        }
    }
}
