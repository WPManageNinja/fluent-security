<?php

namespace FluentAuth\App\Services\IntegrityChecker;

/**
 * The official core checksums could not be obtained, so there is nothing to compare against.
 *
 * Its own class because the scan screen has to say something useful about it, and the two
 * reasons want different sentences: wordpress.org was not reachable, or wordpress.org has
 * nothing published for this build. Neither has anything to do with the alert relay, which is
 * what the old message sent people off to reconnect.
 *
 * The message is already translated and already addressed to the site owner - a caller shows
 * it as-is. getReason() is for callers that branch; getDetail() is the technical half, worth
 * logging but not worth putting in front of anyone.
 */
class ChecksumException extends \Exception
{
    const UNREACHABLE = 'unreachable';

    const UNPUBLISHED = 'unpublished';

    protected $reason;

    protected $detail;

    public function __construct($reason, $message, $detail = '')
    {
        parent::__construct($message);

        $this->reason = $reason;
        $this->detail = $detail;
    }

    public function getReason()
    {
        return $this->reason;
    }

    public function getDetail()
    {
        return $this->detail;
    }
}
