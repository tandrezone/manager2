<?php

declare(strict_types=1);

namespace Manager2\Notify;

interface Transport
{
    public function name(): string;

    /** @throws \RuntimeException on delivery failure */
    public function send(Notification $notification): void;
}
