package com.bendoerr.saltedmocha;

/**
 * <p>CryptoException class.</p>
 */
public class CryptoException extends Exception {

    /**
     * <p>exception.</p>
     *
     * @param reason a {@link java.lang.String} object.
     * @return a {@link com.bendoerr.saltedmocha.CryptoException} object.
     */
    public static CryptoException exception(String reason) {
        return new CryptoException(reason);
    }

    /**
     * <p>exceptionOf.</p>
     *
     * @param cause a {@link java.lang.Throwable} object.
     * @return a {@link com.bendoerr.saltedmocha.CryptoException} object.
     */
    public static CryptoException exceptionOf(Throwable cause) {
        return new CryptoException(cause);
    }

    /**
     * <p>Constructor for CryptoException.</p>
     */
    public CryptoException() {
    }

    /**
     * <p>Constructor for CryptoException.</p>
     *
     * @param message a {@link java.lang.String} object.
     */
    public CryptoException(String message) {
        super(message);
    }

    /**
     * <p>Constructor for CryptoException.</p>
     *
     * @param message a {@link java.lang.String} object.
     * @param cause a {@link java.lang.Throwable} object.
     */
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * <p>Constructor for CryptoException.</p>
     *
     * @param cause a {@link java.lang.Throwable} object.
     */
    public CryptoException(Throwable cause) {
        super(cause);
    }

    /**
     * <p>Constructor for CryptoException.</p>
     *
     * @param message a {@link java.lang.String} object.
     * @param cause a {@link java.lang.Throwable} object.
     * @param enableSuppression a boolean.
     * @param writableStackTrace a boolean.
     */
    public CryptoException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
