package me.jamesjulich.saltpack4j.exception;

public class SaltpackException extends Exception
{
    public SaltpackException(String message)
    {
        super(message);
    }

    public SaltpackException(String message, Exception e)
    {
        super(message, e);
    }
}
