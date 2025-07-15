<?php

namespace SolidOidc;

/**
 * Custom exception class for SolidOidc operations
 */
class SolidOidcException extends \Exception
{
    private ?string $errorCode;
    private ?array $context;

    public function __construct(string $message = "", string $errorCode = null, array $context = null, int $code = 0, \Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->errorCode = $errorCode;
        $this->context = $context;
    }

    /**
     * Get the error code
     * 
     * @return string|null
     */
    public function getErrorCode(): ?string
    {
        return $this->errorCode;
    }

    /**
     * Get the error context
     * 
     * @return array|null
     */
    public function getContext(): ?array
    {
        return $this->context;
    }

    /**
     * Create an exception for discovery failures
     * 
     * @param string $message
     * @param array|null $context
     * @return static
     */
    public static function discoveryFailed(string $message, ?array $context = null): self
    {
        return new self($message, 'DISCOVERY_FAILED', $context);
    }

    /**
     * Create an exception for authentication failures
     * 
     * @param string $message
     * @param array|null $context
     * @return static
     */
    public static function authenticationFailed(string $message, ?array $context = null): self
    {
        return new self($message, 'AUTHENTICATION_FAILED', $context);
    }

    /**
     * Create an exception for token validation failures
     * 
     * @param string $message
     * @param array|null $context
     * @return static
     */
    public static function tokenValidationFailed(string $message, ?array $context = null): self
    {
        return new self($message, 'TOKEN_VALIDATION_FAILED', $context);
    }

    /**
     * Create an exception for DPoP failures
     * 
     * @param string $message
     * @param array|null $context
     * @return static
     */
    public static function dpopFailed(string $message, ?array $context = null): self
    {
        return new self($message, 'DPOP_FAILED', $context);
    }

    /**
     * Create an exception for HTTP request failures
     * 
     * @param string $message
     * @param int $httpCode
     * @param array|null $context
     * @return static
     */
    public static function httpRequestFailed(string $message, int $httpCode, ?array $context = null): self
    {
        return new self($message, 'HTTP_REQUEST_FAILED', array_merge($context ?? [], ['http_code' => $httpCode]));
    }
}

