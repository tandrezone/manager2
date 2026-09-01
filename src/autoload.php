<?php

declare(strict_types=1);

/**
 * Minimal PSR-4 autoloader for Manager2\ => src/.
 *
 * Present so the project runs with zero Composer dependencies, as specified
 * ("native modern PHP"). Swap for Composer's autoloader the moment you add a
 * third-party package — do not maintain both.
 */
spl_autoload_register(static function (string $class): void {
    $prefix = 'Manager2\\';

    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $path = __DIR__ . '/' . str_replace('\\', '/', $relative) . '.php';

    if (is_file($path)) {
        require $path;
    }
});
