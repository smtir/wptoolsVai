<?php
/**
 * WordPress Tools Kit - Advanced File Management System
 * 
 * This application provides comprehensive file and directory management capabilities
 * including safe deletion, backup/restore, trash management, and WordPress core operations.
 * 
 * @author Tawhidul Islam
 * @version 2.1.0
 * @since 2024-01-01
 * @license MIT
 */

// Enable error reporting for debugging
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(0);

/**
 * Environment probe for shared / cPanel hosting.
 *
 * Long or numerous operations must never fatally break the request. On cPanel
 * the PHP process is typically capped (max_execution_time ~30s, limited memory,
 * shell functions disabled). Env::init() records those limits once so batch
 * handlers can budget their work and degrade gracefully instead of dying.
 */
class Env {
    private static $initialized = false;
    private static $disabledFunctions = [];
    private static $maxExecutionTime = 30;
    private static $memoryLimitBytes = 0;

    public static function init() {
        if (self::$initialized) return;
        self::$initialized = true;

        // Parse the disabled_functions list once (common on cPanel/shared hosts).
        $disabled = ini_get('disable_functions');
        self::$disabledFunctions = array_filter(array_map('trim',
            explode(',', strtolower((string)$disabled))));

        // Record the server's execution-time cap so JobBudget can stay under it.
        $configured = (int) ini_get('max_execution_time');
        // A value of 0 means "unlimited" (usually CLI); assume a safe cap anyway.
        self::$maxExecutionTime = ($configured > 0) ? $configured : 30;

        // Best-effort: give ourselves the most time the host allows per request.
        // Wrapped in a guard because some hosts disable set_time_limit itself.
        if (self::isFunctionAvailable('set_time_limit')) {
            @set_time_limit(self::$maxExecutionTime);
        }

        self::$memoryLimitBytes = self::parseBytes(ini_get('memory_limit'));
    }

    /** True if a PHP function exists AND is not in disable_functions. */
    public static function isFunctionAvailable($fn) {
        return function_exists($fn)
            && !in_array(strtolower($fn), self::$disabledFunctions, true);
    }

    /** Any shell exec capability present? Used to degrade the command tool. */
    public static function canRunShell() {
        return self::isFunctionAvailable('shell_exec')
            || self::isFunctionAvailable('exec')
            || self::isFunctionAvailable('system');
    }

    /** Server execution cap in seconds (never 0/unlimited). */
    public static function maxExecutionTime() {
        return self::$maxExecutionTime;
    }

    /** Remaining memory headroom in bytes; PHP_INT_MAX if unlimited. */
    public static function memoryHeadroom() {
        if (self::$memoryLimitBytes <= 0) return PHP_INT_MAX;
        return self::$memoryLimitBytes - memory_get_usage(true);
    }

    /** Convert an ini shorthand size ("256M", "1G") to bytes. */
    public static function parseBytes($value) {
        $value = trim((string)$value);
        if ($value === '' || $value === '-1') return 0; // unlimited
        $unit = strtolower(substr($value, -1));
        $num  = (float) $value;
        switch ($unit) {
            case 'g': $num *= 1024;
            case 'm': $num *= 1024;
            case 'k': $num *= 1024;
        }
        return (int) $num;
    }
}
Env::init();

// Set exception handler for centralized error handling
set_exception_handler(function($exception) {
    Logger::log('ERROR', $exception->getMessage(), [
        'file' => $exception->getFile(),
        'line' => $exception->getLine(),
        'trace' => $exception->getTraceAsString()
    ]);
    
    if (SecurityHelper::isAjaxRequest()) {
        SecurityHelper::jsonError('An error occurred: ' . $exception->getMessage(), 500);
    } else {
        echo '<div style="color: red; padding: 20px;">An error occurred. Please check the logs.</div>';
    }
});

/**
 * Security Helper Class
 * 
 * Handles security-related operations including session management,
 * AJAX request validation, CSRF protection, and input sanitization.
 */
class SecurityHelper {
    /**
     * Ensures session is started for user authentication
     */
    public static function ensureSession() {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
    }

    /**
     * Validates if the current request is an AJAX request
     * 
     * @return bool True if AJAX request, false otherwise
     */
    public static function isAjaxRequest() {
        return isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
               strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
    }
    
    /**
     * Sends JSON error response and terminates execution
     * 
     * @param string|array $msg Error message or array of errors
     * @param int $code HTTP status code (default: 400)
     */
    public static function jsonError($msg, $code = 400) {
        http_response_code($code);
        header('Content-Type: application/json');
        echo json_encode(['error' => $msg]);
        exit;
    }
    
    /**
     * Sends JSON success response and terminates execution
     * 
     * @param array $data Response data
     * @param int $code HTTP status code (default: 200)
     */
    public static function jsonResponse($data, $code = 200) {
        http_response_code($code);
        header('Content-Type: application/json');
        echo json_encode($data);
        exit;
    }
    
    /**
     * Validates and sanitizes file paths to prevent security vulnerabilities
     * 
     * @param string $path The path to validate
     * @return string Sanitized path
     * @throws SecurityException If path contains dangerous characters
     */
    public static function validatePath($path) {
        // Remove null bytes
        $path = str_replace("\0", '', $path);
        
        // Normalize path separators
        $path = str_replace(['\\', '//'], '/', $path);
        
        // Check for directory traversal
        if (preg_match('/\.\./', $path)) {
            throw new SecurityException('Directory traversal detected in path: ' . $path);
        }
        
        // Check for dangerous characters while allowing Windows drive letters and common path characters
        $dangerousChars = ['<', '>', '"', '|', '?', '*', '&', ';', '(', ')', '{', '}', '[', ']', '`', '$', '!'];
        foreach ($dangerousChars as $char) {
            if (strpos($path, $char) !== false) {
                throw new SecurityException('Dangerous character "' . $char . '" found in path: ' . $path);
            }
        }
        
        // Allow Windows drive letters (C:, D:, etc.) and common path characters
        // This regex allows: letters, numbers, underscores, hyphens, dots, slashes, colons (for drive letters), and spaces
        if (!preg_match('/^[a-zA-Z0-9_\-\/\.\:\s]+$/', $path)) {
            throw new SecurityException('Invalid characters in path: ' . $path);
        }
        
        return $path;
    }
}

/**
 * Custom Security Exception Class
 */
class SecurityException extends Exception {}

/**
 * Custom File Operation Exception Class
 */
class FileOperationException extends Exception {}

/**
 * File Search & Filtering Manager
 * 
 * Provides advanced file search capabilities with filtering options
 * for size, date, and content-based searches.
 */
class FileSearchManager {
    /**
     * Search files by name pattern (supports regex)
     * 
     * @param string $directory Directory to search in
     * @param string $pattern Search pattern (supports regex)
     * @param bool $recursive Search recursively
     * @return array Array of matching files
     */
    public static function searchByName($directory, $pattern, $recursive = true) {
        $results = [];
        
        // Convert simple pattern to regex pattern
        $regexPattern = '/' . preg_quote($pattern, '/') . '/i';
        
        // Log the pattern for debugging
        Logger::logDebug("Search pattern details", [
            'original_pattern' => $pattern,
            'regex_pattern' => $regexPattern,
            'pattern_length' => strlen($pattern)
        ]);
        
        // Log for debugging
        Logger::logDebug("SearchByName called", [
            'directory' => $directory,
            'pattern' => $pattern,
            'regex_pattern' => $regexPattern,
            'recursive' => $recursive
        ]);
        
        if ($recursive) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
        } else {
            $iterator = new DirectoryIterator($directory);
        }
        
        foreach ($iterator as $file) {
            $filename = $file->getFilename();
            $isDir = $file->isDir();
            
            // Log every file/folder being checked
            Logger::logDebug("Checking item", [
                'filename' => $filename,
                'is_dir' => $isDir,
                'full_path' => $file->getPathname(),
                'matches_pattern' => preg_match($regexPattern, $filename) ? 'YES' : 'NO'
            ]);
            
            // Check if filename matches the pattern
            if (preg_match($regexPattern, $filename)) {
                $result = [
                    'name' => $filename,
                    'path' => str_replace($directory, '', $file->getPathname()),
                    'size' => $file->getSize(),
                    'modified' => $file->getMTime(),
                    'permissions' => substr(sprintf('%o', $file->getPerms()), -4),
                    'type' => $isDir ? 'folder' : 'file'
                ];
                
                $results[] = $result;
                
                // Log each match for debugging
                Logger::logDebug("Search match found", [
                    'name' => $filename,
                    'type' => $isDir ? 'folder' : 'file',
                    'path' => $result['path'],
                    'is_dir' => $isDir,
                    'full_path' => $file->getPathname()
                ]);
            }
        }
        
        // Log final results
        Logger::logDebug("SearchByName completed", [
            'total_results' => count($results),
            'folders' => count(array_filter($results, function($r) { return $r['type'] === 'folder'; })),
            'files' => count(array_filter($results, function($r) { return $r['type'] === 'file'; }))
        ]);
        
        return $results;
    }
    
    /**
     * Filter files by size range
     * 
     * @param array $files Array of file information
     * @param int $minSize Minimum size in bytes
     * @param int $maxSize Maximum size in bytes
     * @return array Filtered files
     */
    public static function filterBySize($files, $minSize = 0, $maxSize = null) {
        return array_filter($files, function($file) use ($minSize, $maxSize) {
            $size = $file['size'] ?? 0;
            return $size >= $minSize && ($maxSize === null || $size <= $maxSize);
        });
    }
    
    /**
     * Filter files by modification date
     * 
     * @param array $files Array of file information
     * @param int $startDate Start timestamp
     * @param int $endDate End timestamp
     * @return array Filtered files
     */
    public static function filterByDate($files, $startDate = null, $endDate = null) {
        return array_filter($files, function($file) use ($startDate, $endDate) {
            $modified = $file['modified'] ?? 0;
            return ($startDate === null || $modified >= $startDate) && 
                   ($endDate === null || $modified <= $endDate);
        });
    }
    
    /**
     * Search files by content (text search)
     * 
     * @param string $directory Directory to search in
     * @param string $searchText Text to search for
     * @param array $extensions File extensions to search (e.g., ['php', 'txt'])
     * @return array Array of files containing the text
     */
    public static function searchByContent($directory, $searchText, $extensions = []) {
        $results = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS));
        
        foreach ($iterator as $file) {
            if (!$file->isFile()) continue;
            
            $extension = pathinfo($file->getFilename(), PATHINFO_EXTENSION);
            if (!empty($extensions) && !in_array(strtolower($extension), array_map('strtolower', $extensions))) {
                continue;
            }
            
            $content = file_get_contents($file->getPathname());
            if ($content !== false && stripos($content, $searchText) !== false) {
                $results[] = [
                    'name' => $file->getFilename(),
                    'path' => str_replace($directory, '', $file->getPathname()),
                    'size' => $file->getSize(),
                    'modified' => $file->getMTime(),
                    'permissions' => substr(sprintf('%o', $file->getPerms()), -4),
                    'type' => 'file'
                ];
            }
        }
        
        return $results;
    }
}

/**
 * File Permissions Manager
 * 
 * Handles file and directory permission management with security validation.
 */
class PermissionManager {
    /**
     * Set permissions for a file or directory
     * 
     * @param string $path Path to file or directory
     * @param int $permissions Octal permissions (e.g., 0644, 0755)
     * @param bool $recursive Apply recursively to directories
     * @return array Result with status and details
     */
    public static function setPermissions($path, $permissions, $recursive = false) {
        try {
            // Handle Windows paths more gracefully
            $path = str_replace('\\', '/', $path);
            
            // Skip validation for Windows drive letters and common paths
            $realPath = realpath($path);
            
            if (!$realPath || !file_exists($realPath)) {
                return ['status' => 'error', 'message' => 'File or directory not found'];
            }
            
            if ($recursive && is_dir($realPath)) {
                $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($realPath, RecursiveDirectoryIterator::SKIP_DOTS));
                foreach ($iterator as $item) {
                    if (!chmod($item->getPathname(), $permissions)) {
                        Logger::logError("Failed to set permissions", [
                            'path' => $item->getPathname(),
                            'permissions' => $permissions
                        ]);
                    }
                }
            }
            
            if (chmod($realPath, $permissions)) {
                Logger::logAction("Permissions set successfully", [
                    'path' => $path,
                    'permissions' => $permissions,
                    'recursive' => $recursive
                ]);
                return ['status' => 'success', 'message' => 'Permissions set successfully'];
            } else {
                return ['status' => 'error', 'message' => 'Failed to set permissions'];
            }
            
        } catch (Exception $e) {
            Logger::logError("Permission setting failed", [
                'path' => $path,
                'error' => $e->getMessage()
            ]);
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }
    
    /**
     * Fix common permission issues for WordPress
     * 
     * Sets correct permissions for WordPress files and directories:
     * - Directories: 0755
     * - Files: 0644
     * - wp-config.php: 0600
     * - wp-content/uploads/: 0775 (needs write access)
     * 
     * @param string $baseDir WordPress base directory
     * @return array Results of permission fixes
     */
    public static function fixWordPressPermissions($baseDir) {
        $results = [];
        $foundWordPressFiles = false;
        $missingFiles = [];

        // The tool may live inside the WP root or one level below it (e.g. /tools/).
        // Resolve the actual WordPress root by locating wp-config.php so the fix
        // targets the real installation instead of just this script's folder.
        $candidates = [$baseDir, dirname($baseDir)];
        foreach ($candidates as $c) {
            if (is_dir($c) && file_exists($c . '/wp-config.php')) {
                $baseDir = realpath($c);
                break;
            }
        }

        // Directories that need special handling
        $specialDirs = [
            'wp-content/uploads' => 0775, // needs write access
        ];

        /**
         * Helper: recursively set permissions on all files and dirs
         */
        $fixRecursive = function($dir, $dirPerms, $filePerms) use (&$fixRecursive, &$results) {
            try {
                $realDir = realpath($dir);
                if (!$realDir || !is_dir($realDir)) return;

                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($realDir, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );

                $dirCount = 0;
                $fileCount = 0;
                foreach ($iterator as $item) {
                    $path = $item->getPathname();
                    if ($item->isDir()) {
                        if (chmod($path, $dirPerms)) $dirCount++;
                    } else {
                        if (chmod($path, $filePerms)) $fileCount++;
                    }
                }
                $results[$dir . '/'] = [
                    'status' => 'success',
                    'message' => "Directories: $dirCount, Files: $fileCount",
                    'dirs_fixed' => $dirCount,
                    'files_fixed' => $fileCount,
                ];
            } catch (Exception $e) {
                $results[$dir . '/'] = ['status' => 'error', 'message' => $e->getMessage()];
            }
        };

        // 1. Fix wp-config.php — owner read/write, group read.
        // NOTE: 0640 (not 0600) so hosts where the web server runs as a separate
        // user in the same group can still read it. 0600 breaks the site on
        // non-suEXEC / mod_php setups ("Error establishing a database connection").
        $wpConfig = $baseDir . '/wp-config.php';
        if (file_exists($wpConfig)) {
            if (chmod($wpConfig, 0640)) {
                $results['wp-config.php'] = ['status' => 'success', 'message' => 'Set to 0640'];
            } else {
                $results['wp-config.php'] = ['status' => 'error', 'message' => 'chmod failed'];
            }
            $foundWordPressFiles = true;
        } else {
            $missingFiles[] = 'wp-config.php';
        }

        // 2. Fix wp-content — 0755 dirs, 0644 files recursive.
        // Done BEFORE uploads so the uploads-specific pass below is not overwritten.
        $wpContent = $baseDir . '/wp-content';
        if (is_dir($wpContent)) {
            $fixRecursive($wpContent, 0755, 0644);
            $foundWordPressFiles = true;
        } else {
            $missingFiles[] = 'wp-content';
        }

        // 3. Fix wp-content/uploads — 0775 dirs / 0664 files (needs write access).
        // Applied last so it takes precedence over the wp-content pass above.
        $uploadsDir = $baseDir . '/wp-content/uploads';
        if (is_dir($uploadsDir)) {
            $fixRecursive($uploadsDir, 0775, 0664);
            $foundWordPressFiles = true;
        } else {
            $missingFiles[] = 'wp-content/uploads';
        }

        // 4. Fix root-level files — 0644
        $rootFiles = ['index.php', 'xmlrpc.php', 'license.txt', 'readme.html'];
        foreach ($rootFiles as $f) {
            $path = $baseDir . '/' . $f;
            if (file_exists($path)) {
                if (chmod($path, 0644)) {
                    $results[$f] = ['status' => 'success', 'message' => 'Set to 0644'];
                } else {
                    $results[$f] = ['status' => 'error', 'message' => 'chmod failed'];
                }
                $foundWordPressFiles = true;
            }
        }

        // 5. Fix root-level directories — 0755
        $rootDirs = ['wp-admin', 'wp-includes'];
        foreach ($rootDirs as $d) {
            $path = $baseDir . '/' . $d;
            if (is_dir($path)) {
                $fixRecursive($path, 0755, 0644);
                $foundWordPressFiles = true;
            } else {
                $missingFiles[] = $d;
            }
        }

        // Check if any WordPress files were found
        if (!$foundWordPressFiles) {
            $missingList = implode(', ', $missingFiles);
            throw new FileOperationException("WordPress files/folders not found:<br>{$missingList}. Please ensure this is a valid WordPress installation.");
        }

        Logger::logAction("WordPress permissions fixed", ['results' => $results]);
        return $results;
    }
    
    /**
     * Get current permissions for a file or directory
     * 
     * @param string $path Path to check
     * @return array Permission information
     */
    public static function getPermissions($path) {
        try {
            // Handle Windows paths more gracefully
            $path = str_replace('\\', '/', $path);
            
            // Skip validation for Windows drive letters and common paths
            $realPath = realpath($path);
            
            if (!$realPath || !file_exists($realPath)) {
                return ['status' => 'error', 'message' => 'File or directory not found'];
            }
            
            $perms = fileperms($realPath);
            $owner = posix_getpwuid(fileowner($realPath));
            $group = posix_getgrgid(filegroup($realPath));
            
            return [
                'status' => 'success',
                'permissions' => [
                    'octal' => substr(sprintf('%o', $perms), -4),
                    'symbolic' => self::getSymbolicPermissions($perms),
                    'owner' => $owner['name'] ?? 'unknown',
                    'group' => $group['name'] ?? 'unknown',
                    'readable' => is_readable($realPath),
                    'writable' => is_writable($realPath),
                    'executable' => is_executable($realPath)
                ]
            ];
            
        } catch (Exception $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }
    
    /**
     * Convert octal permissions to symbolic format
     * 
     * @param int $perms File permissions
     * @return string Symbolic permissions (e.g., rw-r--r--)
     */
    private static function getSymbolicPermissions($perms) {
        $symbolic = '';
        $symbolic .= ($perms & 0x0100) ? 'r' : '-';
        $symbolic .= ($perms & 0x0080) ? 'w' : '-';
        $symbolic .= ($perms & 0x0040) ? 'x' : '-';
        $symbolic .= ($perms & 0x0020) ? 'r' : '-';
        $symbolic .= ($perms & 0x0010) ? 'w' : '-';
        $symbolic .= ($perms & 0x0008) ? 'x' : '-';
        $symbolic .= ($perms & 0x0004) ? 'r' : '-';
        $symbolic .= ($perms & 0x0002) ? 'w' : '-';
        $symbolic .= ($perms & 0x0001) ? 'x' : '-';
        return $symbolic;
    }
}

/**
 * WordPress System Health Monitor
 * 
 * Monitors WordPress system health, performance, and security.
 */
class SystemHealthManager {
    /**
     * Generate comprehensive system health report
     * 
     * @param string $baseDir WordPress base directory
     * @return array Health report data
     */
    public static function generateHealthReport($baseDir) {
        // Validate that the base directory exists
        if (!is_dir($baseDir)) {
            throw new FileOperationException('Base directory does not exist: ' . $baseDir);
        }
        
        $report = [
            'timestamp' => date('Y-m-d H:i:s'),
            'system' => self::getSystemInfo(),
            'disk' => self::getDiskInfo($baseDir),
            'memory' => self::getMemoryInfo(),
            'wordpress' => self::getWordPressInfo($baseDir),
            'security' => self::getSecurityInfo($baseDir),
            'performance' => self::getPerformanceInfo($baseDir)
        ];
        
        Logger::logAction("System health report generated", ['report' => $report]);
        return $report;
    }
    
    /**
     * Get system information
     * 
     * @return array System info
     */
    private static function getSystemInfo() {
        return [
            'php_version' => PHP_VERSION,
            'php_extensions' => get_loaded_extensions(),
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
            'os' => PHP_OS,
            'max_execution_time' => ini_get('max_execution_time'),
            'memory_limit' => ini_get('memory_limit'),
            'upload_max_filesize' => ini_get('upload_max_filesize'),
            'post_max_size' => ini_get('post_max_size')
        ];
    }
    
    /**
     * Get disk space information
     * 
     * @param string $baseDir Base directory to check
     * @return array Disk info
     */
    private static function getDiskInfo($baseDir) {
        $totalSpace = disk_total_space($baseDir);
        $freeSpace = disk_free_space($baseDir);
        $usedSpace = $totalSpace - $freeSpace;
        
        return [
            'total_space' => self::formatBytes($totalSpace),
            'free_space' => self::formatBytes($freeSpace),
            'used_space' => self::formatBytes($usedSpace),
            'usage_percentage' => round(($usedSpace / $totalSpace) * 100, 2),
            'status' => ($freeSpace < 100 * 1024 * 1024) ? 'warning' : 'good' // Warning if less than 100MB free
        ];
    }
    
    /**
     * Get memory usage information
     * 
     * @return array Memory info
     */
    private static function getMemoryInfo() {
        $memoryUsage = memory_get_usage(true);
        $memoryPeak = memory_get_peak_usage(true);
        $memoryLimit = ini_get('memory_limit');
        
        // Calculate memory limit in bytes
        $memoryLimitBytes = self::parseMemoryLimit($memoryLimit);
        $usagePercentage = ($memoryLimitBytes > 0 && $memoryUsage > 0) ? round(($memoryUsage / $memoryLimitBytes) * 100, 2) : 0;
        
        return [
            'current_usage' => self::formatBytes($memoryUsage),
            'peak_usage' => self::formatBytes($memoryPeak),
            'memory_limit' => $memoryLimit,
            'usage_percentage' => $usagePercentage,
            'status' => ($memoryUsage > 50 * 1024 * 1024) ? 'warning' : 'good' // Warning if using more than 50MB
        ];
    }
    
    /**
     * Get WordPress-specific information
     * 
     * @param string $baseDir WordPress base directory
     * @return array WordPress info
     */
    private static function getWordPressInfo($baseDir) {
        $wpConfig = $baseDir . '/wp-config.php';
        $wpContent = $baseDir . '/wp-content';
        $wpAdmin = $baseDir . '/wp-admin';
        
        $info = [
            'wp_config_exists' => file_exists($wpConfig),
            'wp_content_exists' => is_dir($wpContent),
            'wp_admin_exists' => is_dir($wpAdmin),
            'plugins_count' => 0,
            'themes_count' => 0,
            'uploads_size' => 0
        ];
        
        // Count plugins
        if (is_dir($wpContent . '/plugins')) {
            $plugins = glob($wpContent . '/plugins/*', GLOB_ONLYDIR);
            $info['plugins_count'] = count($plugins);
        }
        
        // Count themes
        if (is_dir($wpContent . '/themes')) {
            $themes = glob($wpContent . '/themes/*', GLOB_ONLYDIR);
            $info['themes_count'] = count($themes);
        }
        
        // Calculate uploads size
        if (is_dir($wpContent . '/uploads')) {
            $info['uploads_size'] = self::calculateDirectorySize($wpContent . '/uploads');
        }
        
        return $info;
    }
    
    /**
     * Get security-related information
     * 
     * @param string $baseDir WordPress base directory
     * @return array Security info
     */
    private static function getSecurityInfo($baseDir) {
        $wpConfig = $baseDir . '/wp-config.php';
        $securityIssues = [];
        
        // Check wp-config.php permissions
        if (file_exists($wpConfig)) {
            $perms = fileperms($wpConfig);
            if (($perms & 0x0177) !== 0) { // Check if others have any permissions
                $securityIssues[] = 'wp-config.php has loose permissions';
            }
        }
        
        // Check for common security files
        $securityFiles = [
            '.htaccess' => 'Missing .htaccess file',
            'wp-content/debug.log' => 'Debug log file exists',
            'wp-content/uploads' => 'Uploads directory writable by web server'
        ];
        
        foreach ($securityFiles as $file => $message) {
            $filePath = $baseDir . '/' . $file;
            if (file_exists($filePath)) {
                if ($file === 'wp-content/debug.log') {
                    $securityIssues[] = $message;
                } elseif ($file === 'wp-content/uploads' && is_writable($filePath)) {
                    $securityIssues[] = $message;
                }
            } elseif ($file === '.htaccess') {
                $securityIssues[] = $message;
            }
        }
        
        return [
            'issues' => $securityIssues,
            'status' => empty($securityIssues) ? 'secure' : 'warning'
        ];
    }
    
    /**
     * Get performance-related information
     * 
     * @param string $baseDir WordPress base directory
     * @return array Performance info
     */
    private static function getPerformanceInfo($baseDir) {
        $wpContent = $baseDir . '/wp-content';
        $performanceIssues = [];
        
        // Check cache directory
        if (is_dir($wpContent . '/cache')) {
            $cacheSize = self::calculateDirectorySize($wpContent . '/cache');
            if ($cacheSize > 100 * 1024 * 1024) { // More than 100MB
                $performanceIssues[] = 'Cache directory is large (' . self::formatBytes($cacheSize) . ')';
            }
        }
        
        // Check for large files
        $largeFiles = self::findLargeFiles($baseDir, 10 * 1024 * 1024); // Files larger than 10MB
        if (!empty($largeFiles)) {
            $performanceIssues[] = 'Found ' . count($largeFiles) . ' large files';
        }
        
        return [
            'issues' => $performanceIssues,
            'large_files' => $largeFiles,
            'status' => empty($performanceIssues) ? 'good' : 'warning'
        ];
    }
    
    /**
     * Calculate directory size recursively
     * 
     * @param string $directory Directory path
     * @return int Size in bytes
     */
    private static function calculateDirectorySize($directory) {
        $size = 0;
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS));
        
        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $size += $file->getSize();
            }
        }
        
        return $size;
    }
    
    /**
     * Find large files in directory
     * 
     * @param string $directory Directory to search
     * @param int $minSize Minimum size in bytes
     * @return array Large files
     */
    private static function findLargeFiles($directory, $minSize) {
        $largeFiles = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS));
        
        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getSize() > $minSize) {
                $largeFiles[] = [
                    'path' => str_replace($directory, '', $file->getPathname()),
                    'size' => self::formatBytes($file->getSize())
                ];
            }
        }
        
        return $largeFiles;
    }
    
    /**
     * Format bytes to human readable format
     * 
     * @param int $bytes Bytes to format
     * @return string Formatted string
     */
    private static function formatBytes($bytes) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        
        $bytes /= pow(1024, $pow);
        
        return round($bytes, 2) . ' ' . $units[$pow];
    }
    
    /**
     * Parse memory limit string to bytes
     * 
     * @param string $memoryLimit Memory limit string (e.g., "128M", "1G")
     * @return int Memory limit in bytes
     */
    private static function parseMemoryLimit($memoryLimit) {
        if (empty($memoryLimit) || $memoryLimit === '-1') {
            return 0; // No limit
        }
        
        $value = (int) $memoryLimit;
        $unit = strtoupper(substr($memoryLimit, -1));
        
        switch ($unit) {
            case 'K':
                return $value * 1024;
            case 'M':
                return $value * 1024 * 1024;
            case 'G':
                return $value * 1024 * 1024 * 1024;
            default:
                return $value; // Assume bytes if no unit
        }
    }
}
/**
 * Helper Utilities Class
 * 
 * Provides centralized helper methods for common operations
 * including error handling, directory management, and validation.
 */
class HelperUtils {
    /**
     * Standardized error response format
     * 
     * @param string $message Error message
     * @param int $code HTTP status code
     * @param array $context Additional context
     */
    public static function sendErrorResponse($message, $code = 400, $context = []) {
        Logger::logError($message, $context);
        SecurityHelper::jsonError($message, $code);
    }
    
    /**
     * Standardized success response format
     * 
     * @param array $data Response data
     * @param int $code HTTP status code
     * @param array $context Additional context
     */
    public static function sendSuccessResponse($data, $code = 200, $context = []) {
        Logger::logAction("Operation completed successfully", $context);
        SecurityHelper::jsonResponse($data, $code);
    }
    
    /**
     * Centralized directory creation with validation
     * 
     * @param string $path Directory path to create
     * @param int $permissions Directory permissions (default: 0755)
     * @return array Result with status and details
     */
    public static function createDirectory($path, $permissions = 0755) {
        try {
            $path = SecurityHelper::validatePath($path);
            
            if (is_dir($path)) {
                return ['status' => 'exists', 'message' => 'Directory already exists'];
            }
            
            if (mkdir($path, $permissions, true)) {
                Logger::logAction("Directory created", [
                    'path' => $path,
                    'permissions' => $permissions
                ]);
                return ['status' => 'created', 'message' => 'Directory created successfully'];
            } else {
                Logger::logError("Failed to create directory", ['path' => $path]);
                return ['status' => 'error', 'message' => 'Failed to create directory'];
            }
            
        } catch (Exception $e) {
            Logger::logError("Directory creation failed", [
                'path' => $path,
                'error' => $e->getMessage()
            ]);
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }
    
    /**
     * Validate file or directory exists and is accessible
     * 
     * @param string $path Path to validate
     * @param bool $requireFile Require it to be a file
     * @param bool $requireDir Require it to be a directory
     * @return array Validation result
     */
    public static function validatePathExists($path, $requireFile = false, $requireDir = false) {
        try {
            // Handle Windows paths more gracefully
            $path = str_replace('\\', '/', $path);
            
            // Skip strict validation for Windows paths
            $realPath = realpath($path);
            
            if (!$realPath || !file_exists($realPath)) {
                return ['valid' => false, 'message' => 'Path does not exist'];
            }
            
            if ($requireFile && !is_file($realPath)) {
                return ['valid' => false, 'message' => 'Path is not a file'];
            }
            
            if ($requireDir && !is_dir($realPath)) {
                return ['valid' => false, 'message' => 'Path is not a directory'];
            }
            
            return ['valid' => true, 'realPath' => $realPath];
            
        } catch (Exception $e) {
            return ['valid' => false, 'message' => $e->getMessage()];
        }
    }
    
    /**
     * Validate session exists and is valid
     * 
     * @param string $type Session type
     * @param string $sessionId Session ID
     * @return array Validation result
     */
    public static function validateSession($type, $sessionId) {
        $data = SessionManager::loadSession($type, $sessionId);
        if (!$data) {
            return ['valid' => false, 'message' => 'Session not found'];
        }
        return ['valid' => true, 'data' => $data];
    }
    
    /**
     * Format file size for display
     * 
     * @param int $bytes Size in bytes
     * @return string Formatted size
     */
    public static function formatFileSize($bytes) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        
        $bytes /= pow(1024, $pow);
        return round($bytes, 2) . ' ' . $units[$pow];
    }
    
    /**
     * Get file information array
     * 
     * @param string $filePath Path to file
     * @param string $baseDir Base directory for relative paths
     * @return array File information
     */
    public static function getFileInfo($filePath, $baseDir = null) {
        $info = [
            'name' => basename($filePath),
            'path' => $filePath,
            'size' => 0,
            'modified' => 0,
            'permissions' => '0000',
            'type' => 'unknown'
        ];
        
        if (file_exists($filePath)) {
            $info['size'] = filesize($filePath);
            $info['modified'] = filemtime($filePath);
            $info['permissions'] = substr(sprintf('%o', fileperms($filePath)), -4);
            $info['type'] = is_dir($filePath) ? 'directory' : 'file';
            
            if ($baseDir) {
                $info['relativePath'] = str_replace($baseDir, '', $filePath);
            }
        }
        
        return $info;
    }
}

/**
 * Logger Class
 * 
 * Provides centralized logging functionality with different log levels
 * and structured data logging for debugging and audit purposes.
 */
class Logger {
    private static $logLevels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'];
    
    /**
     * Logs a message with specified level and context
     * 
     * @param string $level Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
     * @param string $message Log message
     * @param array $context Additional context data
     */
    public static function log($level, $message, $context = []) {
        $level = strtoupper($level);
        if (!in_array($level, self::$logLevels)) {
            $level = 'INFO';
        }
        
        $entry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'level' => $level,
            'message' => $message,
            'context' => $context,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ];
        
        $logFile = __DIR__ . '/app.log';
        $logEntry = json_encode($entry) . "\n";
        
        try {
            if (!is_writable(dirname($logFile)) && !file_exists($logFile)) {
                    touch($logFile);
                    chmod($logFile, 0666);
                }
            
            if (is_writable($logFile)) {
                file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
            }
        } catch (Exception $e) {
            // Silently fail - logging is not critical for functionality
            error_log("Logger error: " . $e->getMessage());
        }
    }
    
    /**
     * Logs user actions for audit purposes
     * 
     * @param string $action Description of the action performed
     * @param array $details Additional details about the action
     */
    public static function logAction($action, $details = []) {
        self::log('INFO', $action, array_merge($details, ['type' => 'user_action']));
    }
    
    /**
     * Logs debug information for troubleshooting
     * 
     * @param string $message Debug message
     * @param array $context Additional context
     */
    public static function logDebug($message, $context = []) {
        self::log('DEBUG', $message, array_merge($context, ['type' => 'debug']));
    }
    
    /**
     * Logs errors with full context
     * 
     * @param string $message Error message
     * @param array $context Additional context
     */
    public static function logError($message, $context = []) {
        self::log('ERROR', $message, array_merge($context, ['type' => 'error']));
    }
    
    /**
     * Logs security-related events
     * 
     * @param string $message Security message
     * @param array $context Additional context
     */
    public static function logSecurity($message, $context = []) {
        self::log('WARNING', $message, array_merge($context, ['type' => 'security']));
    }
}
/**
 * File Helper Class
 * 
 * Provides optimized file system operations with comprehensive error handling,
 * security validation, and batch processing capabilities.
 */
class FileHelper
{
    /**
     * Validates if a path is safe for file operations
     * 
     * Checks for directory traversal attempts, null bytes, and invalid characters
     * to prevent security vulnerabilities.
     * 
     * @param string $path The path to validate
     * @return bool True if path is safe, false otherwise
     * 
     * @example
     * $safe = FileHelper::isValidRelativePath('../config.php'); // false
     * $safe = FileHelper::isValidRelativePath('wp-content/plugins'); // true
     */
    public static function isValidRelativePath($path)
    {
        // Prevent directory traversal
        if (strpos($path, "..") !== false || strpos($path, "\0") !== false) {
            return false;
        }
        
        // Check for dangerous characters
        $dangerousChars = ['<', '>', '"', '|', '?', '*', '&', ';', '(', ')', '{', '}', '[', ']', '`', '$', '!'];
        foreach ($dangerousChars as $char) {
            if (strpos($path, $char) !== false) {
                return false;
            }
        }
        
        // Allow safe characters including spaces and dots
        if (preg_match('/^[a-zA-Z0-9_\-\/\.\s]+$/', $path) !== 1) {
            return false;
        }
        
        // Prevent absolute paths
        if (strpos($path, "/") === 0 || strpos($path, "\\") === 0) {
            return false;
        }
        
        return true;
    }

    /**
     * Normalizes path separators to forward slashes
     * 
     * @param string $path Path to normalize
     * @return string Normalized path
     */
    public static function normalizePath($path)
    {
        return str_replace(['\\', '//'], '/', $path);
    }

    /**
     * Deletes a folder and all its contents recursively
     * 
     * This method safely removes a directory and all its subdirectories and files.
     * It includes comprehensive error handling and logging for debugging.
     * 
     * @param string $folderPath Path to the folder to delete
     * @return array Status information with 'status' and 'details' keys
     * 
     * @throws FileOperationException When folder path is invalid or inaccessible
     * 
     * @example
     * $result = FileHelper::deleteFolder('wp-content/cache');
     * if ($result['status'] === 'Deleted') {
     *     echo "Folder deleted successfully";
     * } else {
     *     echo "Error: " . $result['details'];
     * }
     */
    public static function deleteFolder($folderPath)
    {
        try {
            // Validate and normalize path
            $folderPath = SecurityHelper::validatePath($folderPath);
        $folderPath = self::normalizePath($folderPath);
        $originalPath = $folderPath;
        $folderPath = realpath($folderPath);
        $folderPath = self::normalizePath($folderPath);
            
        Logger::logDebug("deleteFolder: original=$originalPath resolved=$folderPath exists=" . (is_dir($folderPath) ? 'yes' : 'no'));
            
        if (!$folderPath || !is_dir($folderPath)) {
            return [
                'status' => 'Folder not found',
                'details' => 'Folder does not exist or is not a directory.'
            ];
        }
            
            $errors = [];
            $deletedCount = 0;
            
            // Use RecursiveIteratorIterator for efficient traversal
        $items = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($folderPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
            
        foreach ($items as $item) {
            $path = $item->getRealPath();
                
            if ($item->isDir()) {
                if (!@rmdir($path)) {
                    $err = error_get_last();
                    $errors[] = "Failed to remove directory: $path" . ($err ? ' - ' . $err['message'] : '');
                    } else {
                        $deletedCount++;
                }
            } else {
                $res = @unlink($path);
                Logger::logDebug("unlink: $path => " . ($res ? 'OK' : 'FAIL'));
                if (!$res) {
                    $err = error_get_last();
                    $errors[] = "Failed to delete file: $path" . ($err ? ' - ' . $err['message'] : '');
                    } else {
                        $deletedCount++;
                }
            }
        }
            
            // Remove the main directory
        $finalRes = @rmdir($folderPath);
        Logger::logDebug("rmdir final: $folderPath => " . ($finalRes ? 'OK' : 'FAIL'));
        if (!$finalRes) {
            $err = error_get_last();
            $errors[] = "Failed to remove directory: $folderPath" . ($err ? ' - ' . $err['message'] : '');
            } else {
                $deletedCount++;
        }
            
        if (empty($errors)) {
                Logger::logAction("Folder deleted successfully", [
                    'path' => $originalPath,
                    'items_deleted' => $deletedCount
                ]);
                return [ 'status' => 'Deleted', 'details' => "Deleted $deletedCount items" ];
        } else {
                Logger::logError("Folder deletion failed", [
                    'path' => $originalPath,
                    'errors' => $errors
                ]);
            return [ 'status' => 'Failed to delete', 'details' => implode("\n", $errors) ];
            }
            
        } catch (Exception $e) {
            Logger::logError("Exception in deleteFolder", [
                'path' => $folderPath ?? 'unknown',
                'error' => $e->getMessage()
            ]);
            throw new FileOperationException("Failed to delete folder: " . $e->getMessage());
        }
    }

    /**
     * Deletes multiple folders with optimized batch processing
     * 
     * Processes folders in batches for better performance and provides
     * detailed results for each operation.
     * 
     * @param array $folders Array of folder paths to delete
     * @param int $batchSize Number of folders to process in each batch (default: 10)
     * @return array Results for each folder operation
     */
    public static function deleteFolders(array $folders, $batchSize = 10)
    {
        $results = [];
        $totalFolders = count($folders);
        
        Logger::logAction("Starting batch folder deletion", [
            'total_folders' => $totalFolders,
            'batch_size' => $batchSize
        ]);
        
        // Process in batches for better performance
        for ($i = 0; $i < $totalFolders; $i += $batchSize) {
            $batch = array_slice($folders, $i, $batchSize);
            
            foreach ($batch as $folder) {
                try {
            $folder = self::normalizePath($folder);
            $result = self::deleteFolder($folder);
            $results[$folder] = $result;
                } catch (Exception $e) {
                    Logger::logError("Exception in batch folder deletion", [
                        'folder' => $folder,
                        'error' => $e->getMessage()
                    ]);
                    $results[$folder] = [
                        'status' => 'Exception',
                        'details' => $e->getMessage()
                    ];
                }
            }
            
            // Small delay between batches to prevent server overload
            if ($i + $batchSize < $totalFolders) {
                usleep(100000); // 0.1 second delay
            }
        }
        
        Logger::logAction("Completed batch folder deletion", [
            'total_folders' => $totalFolders,
            'successful' => count(array_filter($results, function($r) { return $r['status'] === 'Deleted'; })),
            'failed' => count(array_filter($results, function($r) { return $r['status'] !== 'Deleted'; }))
        ]);
        
        return $results;
    }

    /**
     * Deletes multiple files with optimized batch processing
     * 
     * Processes files in batches for better performance and includes
     * safety checks to prevent self-deletion.
     * 
     * @param array $files Array of file paths to delete
     * @param int $batchSize Number of files to process in each batch (default: 20)
     * @return array Results for each file operation
     */
    public static function deleteFiles(array $files, $batchSize = 20)
    {
        $results = [];
        $selfPath = self::normalizePath(realpath(__FILE__));
        $totalFiles = count($files);
        
        Logger::logAction("Starting batch file deletion", [
            'total_files' => $totalFiles,
            'batch_size' => $batchSize
        ]);
        
        // Process in batches for better performance
        for ($i = 0; $i < $totalFiles; $i += $batchSize) {
            $batch = array_slice($files, $i, $batchSize);
            
            foreach ($batch as $file) {
                try {
            $file = self::normalizePath($file);
            $path = self::normalizePath(realpath($file));
                    
            if (!$path || !file_exists($file)) {
                $results[$file] = [ 'status' => 'Not found', 'details' => 'File does not exist.' ];
            } elseif ($path === $selfPath) {
                        $results[$file] = [ 
                            'status' => 'Cannot delete this script', 
                            'details' => 'This script cannot delete itself.' 
                        ];
            } elseif (!@unlink($path)) {
                $err = error_get_last();
                        $results[$file] = [ 
                            'status' => 'Failed to delete', 
                            'details' => $err ? $err['message'] : 'Unknown error.' 
                        ];
            } else {
                        $results[$file] = [ 'status' => 'Deleted', 'details' => 'File deleted successfully' ];
                    }
                } catch (Exception $e) {
                    Logger::logError("Exception in batch file deletion", [
                        'file' => $file,
                        'error' => $e->getMessage()
                    ]);
                    $results[$file] = [
                        'status' => 'Exception',
                        'details' => $e->getMessage()
                    ];
                }
            }
            
            // Small delay between batches to prevent server overload
            if ($i + $batchSize < $totalFiles) {
                usleep(50000); // 0.05 second delay
            }
        }
        
        Logger::logAction("Completed batch file deletion", [
            'total_files' => $totalFiles,
            'successful' => count(array_filter($results, function($r) { return $r['status'] === 'Deleted'; })),
            'failed' => count(array_filter($results, function($r) { return $r['status'] !== 'Deleted'; }))
        ]);
        
        return $results;
    }

    public static function restoreCopy($src, $dst) {
        $src = self::normalizePath($src);
        $dst = self::normalizePath($dst);
        if (is_dir($src)) {
            if (!is_dir($dst)) mkdir($dst, 0755, true);
            $items = scandir($src);
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') continue;
                self::restoreCopy($src . '/' . $item, $dst . '/' . $item);
            }
        } else {
            copy($src, $dst);
        }
    }

    public static function getRecursiveDeleteList($path)
    {
        $result = [];
        $real = realpath($path);
        if ($real && is_dir($real)) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($real, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($iterator as $item) {
                $result[] = $item->getPathname();
            }
            $result[] = $real; // include the folder itself
        } elseif ($real && is_file($real)) {
            $result[] = $real;
        }
        return $result;
    }

    public static function backupItem($src, $backupBaseDir, $relativePath = null)
    {
        $srcPath = self::normalizePath(realpath($src));
        $backupBaseDir = self::normalizePath($backupBaseDir);
        if (!$srcPath) return false;
        $dst = $backupBaseDir . '/' . ($relativePath ? ltrim($relativePath, '/\\') : basename($srcPath));
        $dst = self::normalizePath($dst);
        if (is_dir($srcPath)) {
            // Recursively copy directory
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($srcPath, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            foreach ($iterator as $item) {
                $subPath = ltrim(str_replace($srcPath, '', $item->getPathname()), '/\\');
                $targetPath = $dst . ($subPath ? '/' . $subPath : '');
                $targetPath = self::normalizePath($targetPath);
                if ($item->isDir()) {
                    if (!is_dir($targetPath)) mkdir($targetPath, 0755, true);
                }
                else {
                    if (!is_dir(dirname($targetPath))) mkdir(dirname($targetPath), 0755, true);
                    copy($item, $targetPath);
                }
            }
            return true;
        }
        else {
            // Copy file
            if (!is_dir(dirname($dst))) mkdir(dirname($dst), 0755, true);
            return copy($srcPath, $dst);
        }
    }
}
/**
 * Session Manager Class
 * 
 * Provides memory-based session management with file persistence for long-running operations.
 * Optimized for performance with in-memory storage and async file backup.
 */
/**
 * Per-request work budget with adaptive batch sizing.
 *
 * A batch handler creates one JobBudget at the start of the request. Before each
 * item it calls hasTime(); once the elapsed time approaches the server's
 * execution cap, hasTime() returns false and the handler stops early, letting the
 * browser fire the next round-trip. This is what keeps large operations from ever
 * hitting a fatal timeout on cPanel.
 *
 * It also recommends the next batch size based on how fast the current items were
 * processed, so slow servers/large files use small batches and fast ones use big
 * batches — no more hardcoded magic numbers.
 */
class JobBudget {
    private $start;
    private $deadline;          // absolute time we must finish by
    private $minItems;
    private $maxItems;

    public function __construct($minItems = 3, $maxItems = 200) {
        $this->start = microtime(true);
        $this->minItems = $minItems;
        $this->maxItems = $maxItems;

        // Spend at most ~60% of the server cap in one round-trip, capped at 20s.
        // The remaining budget absorbs network latency and JSON encoding so we
        // return a response comfortably before the host kills the process.
        $cap = Env::maxExecutionTime();
        $budget = min(20.0, max(3.0, $cap * 0.6));
        $this->deadline = $this->start + $budget;
    }

    /** Seconds elapsed since this request started working. */
    public function elapsed() {
        return microtime(true) - $this->start;
    }

    /**
     * True while there is still time (and memory headroom) to process another
     * item. Handlers should check this at the top of their batch loop.
     */
    public function hasTime() {
        if (microtime(true) >= $this->deadline) return false;
        // Stop if we are within ~8MB of the memory ceiling to avoid OOM fatals.
        if (Env::memoryHeadroom() < 8 * 1024 * 1024) return false;
        return true;
    }

    /**
     * Recommend how many items the *next* round-trip should request, based on the
     * average time-per-item observed this round. Keeps each round near the budget
     * without exceeding it.
     *
     * @param int $processed Items completed in this round-trip.
     */
    public function nextBatchSize($processed) {
        $processed = (int) $processed;
        if ($processed <= 0) return $this->minItems;

        $perItem = $this->elapsed() / $processed;
        if ($perItem <= 0) return $this->maxItems;

        $window = $this->deadline - $this->start;      // usable seconds per round
        $suggested = (int) floor(($window * 0.9) / $perItem);

        return max($this->minItems, min($this->maxItems, $suggested));
    }
}

class SessionManager {
    // Memory-based session storage for better performance
    private static $sessions = [];
    private static $sessionDirs = [
            'deletion' => __DIR__ . '/deletion_sessions',
            'trash' => __DIR__ . '/trash_sessions',
            'restore' => __DIR__ . '/restore_sessions',
            'scan' => __DIR__ . '/scan_sessions',
            'db_clean' => __DIR__ . '/db_clean_sessions',
            'search_replace' => __DIR__ . '/search_replace_sessions',
            'db_export' => __DIR__ . '/db_export_sessions',
            'integrity' => __DIR__ . '/integrity_sessions',
        ];
    
    /**
     * Gets the session directory for a specific session type
     * 
     * @param string $type Session type (deletion, trash, restore)
     * @return string Path to session directory
     * @throws InvalidArgumentException If session type is invalid
     */
    public static function getSessionDir($type) {
        if (!isset(self::$sessionDirs[$type])) {
            throw new InvalidArgumentException("Invalid session type: $type");
        }
        
        $dir = self::$sessionDirs[$type];
        if (!is_dir($dir)) {
            if (!mkdir($dir, 0755, true)) {
                throw new FileOperationException("Failed to create session directory: $dir");
            }
        }
        
        return $dir;
    }
    
    /**
     * Starts a new session with unique ID
     * 
     * @param string $type Session type
     * @param array $data Initial session data
     * @return string Generated session ID
     */
    public static function startSession($type, $data) {
        $sessionId = bin2hex(random_bytes(16)); // Increased entropy for better security
        
        // Store in memory for fast access
        self::$sessions[$type][$sessionId] = $data;
        
        // Async file backup for persistence
        self::saveSessionToFile($type, $sessionId, $data);
        
        Logger::logAction("Session started", [
            'type' => $type,
            'session_id' => $sessionId,
            'data_size' => count($data)
        ]);
        
        return $sessionId;
    }
    
    /**
     * Gets the file path for a session
     * 
     * @param string $type Session type
     * @param string $sessionId Session ID
     * @return string Path to session file
     */
    public static function getSessionFile($type, $sessionId) {
        $dir = self::getSessionDir($type);
        $sessionId = preg_replace('/[^a-zA-Z0-9]/', '', $sessionId);
        return $dir . '/' . $sessionId . '.json';
    }
    
    /**
     * Loads session data from memory or file
     * 
     * @param string $type Session type
     * @param string $sessionId Session ID
     * @return array|null Session data or null if not found
     */
    public static function loadSession($type, $sessionId) {
        // Try memory first for better performance
        if (isset(self::$sessions[$type][$sessionId])) {
            return self::$sessions[$type][$sessionId];
        }
        
        // Fallback to file
        $file = self::getSessionFile($type, $sessionId);
        if (!file_exists($file)) {
            return null;
        }
        
        try {
            $data = json_decode(file_get_contents($file), true);
            if ($data !== null) {
                // Cache in memory for future access
                self::$sessions[$type][$sessionId] = $data;
                return $data;
            }
        } catch (Exception $e) {
            Logger::logError("Failed to load session from file", [
                'type' => $type,
                'session_id' => $sessionId,
                'file' => $file,
                'error' => $e->getMessage()
            ]);
        }
        
        return null;
    }
    
    /**
     * Saves session data to memory and file
     * 
     * @param string $type Session type
     * @param string $sessionId Session ID
     * @param array $data Session data
     */
    public static function saveSession($type, $sessionId, $data) {
        // Update memory storage
        self::$sessions[$type][$sessionId] = $data;
        
        // Async file backup for persistence
        self::saveSessionToFile($type, $sessionId, $data);
    }
    
    /**
     * Saves session data to file asynchronously
     * 
     * @param string $type Session type
     * @param string $sessionId Session ID
     * @param array $data Session data
     */
    private static function saveSessionToFile($type, $sessionId, $data) {
        try {
        $file = self::getSessionFile($type, $sessionId);
            $jsonData = json_encode($data, JSON_PRETTY_PRINT);
            
            if ($jsonData === false) {
                throw new Exception("Failed to encode session data");
            }
            
            // Use atomic write for data integrity
            $tempFile = $file . '.tmp';
            if (file_put_contents($tempFile, $jsonData, LOCK_EX) === false) {
                throw new Exception("Failed to write session file");
            }
            
            if (!rename($tempFile, $file)) {
                unlink($tempFile);
                throw new Exception("Failed to rename session file");
            }
            
        } catch (Exception $e) {
            Logger::logError("Failed to save session to file", [
                'type' => $type,
                'session_id' => $sessionId,
                'error' => $e->getMessage()
            ]);
        }
    }
    
    /**
     * Deletes a session from memory and file
     * 
     * @param string $type Session type
     * @param string $sessionId Session ID
     */
    public static function deleteSession($type, $sessionId) {
        // Remove from memory
        if (isset(self::$sessions[$type][$sessionId])) {
            unset(self::$sessions[$type][$sessionId]);
        }
        
        // Remove file
        $file = self::getSessionFile($type, $sessionId);
        if (file_exists($file)) {
            if (!unlink($file)) {
                Logger::logError("Failed to delete session file", [
                    'type' => $type,
                    'session_id' => $sessionId,
                    'file' => $file
                ]);
            }
        }
        
        Logger::logAction("Session deleted", [
            'type' => $type,
            'session_id' => $sessionId
        ]);
    }
    
    /**
     * Cleans up expired sessions
     * 
     * @param int $maxAge Maximum age in seconds (default: 3600 = 1 hour)
     */
    public static function cleanupExpiredSessions($maxAge = 3600) {
        $now = time();
        
        foreach (self::$sessionDirs as $type => $dir) {
            if (!is_dir($dir)) continue;
            
            $files = glob($dir . '/*.json');
            foreach ($files as $file) {
                $fileTime = filemtime($file);
                if ($now - $fileTime > $maxAge) {
                    $sessionId = basename($file, '.json');
                    self::deleteSession($type, $sessionId);
                }
            }
        }
    }

    /**
     * Acquires an exclusive, non-blocking lock for a session so that two
     * overlapping "process" round-trips (e.g. the user double-clicks or a stale
     * tab keeps polling) cannot process the same batch twice or corrupt the
     * session JSON. Returns a lock handle on success, or false if another request
     * currently holds the lock — in which case the caller should back off.
     *
     * @return resource|false
     */
    public static function acquireLock($type, $sessionId) {
        $dir = self::getSessionDir($type);
        $sessionId = preg_replace('/[^a-zA-Z0-9]/', '', $sessionId);
        $lockFile = $dir . '/' . $sessionId . '.lock';

        $handle = @fopen($lockFile, 'c');
        if ($handle === false) {
            // If we cannot create a lock file, fail open rather than block work.
            return false;
        }
        if (!flock($handle, LOCK_EX | LOCK_NB)) {
            fclose($handle);
            return false; // Another request owns this session right now.
        }
        return $handle;
    }

    /** Releases a lock handle previously returned by acquireLock(). */
    public static function releaseLock($handle) {
        if (is_resource($handle)) {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}

class TrashManager
{
    public static function listTrash($trashDir)
    {
        $items = [];
        if (!is_dir($trashDir)) return $items;
        $topLevelItems = scandir($trashDir);
        foreach ($topLevelItems as $item) {
            if ($item === '.' || $item === '..') continue;
            $fullPath = $trashDir . DIRECTORY_SEPARATOR . $item;
            $items[] = [
                'name' => $item,
                'path' => $item, // Path is relative to the trash dir
                'type' => is_dir($fullPath) ? 'folder' : 'file'
            ];
        }
        return $items;
    }

    public static function restoreFromTrash($rel, $trashDir, $baseDir)
    {
        $src = $trashDir . '/' . $rel;
        $dst = $baseDir . '/' . $rel;
        if (!file_exists($src) || strpos(realpath($src), $trashDir) !== 0 || strpos(realpath(dirname($dst)), $baseDir) !== 0) {
            return ['error' => 'Invalid restore path'];
        }
        if (!is_dir(dirname($dst))) mkdir(dirname($dst), 0755, true);
        rename($src, $dst);
        return ['success' => true];
    }

    public static function deleteFromTrash($rel, $trashDir)
    {
        $target = $trashDir . '/' . $rel;
        if (!file_exists($target) || strpos(realpath($target), $trashDir) !== 0) {
            return ['error' => 'Invalid trash path'];
        }
        if (is_dir($target)) {
            $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($target, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($rii as $file) {
                if ($file->isDir()) rmdir($file->getRealPath());
                else unlink($file->getRealPath());
            }
            rmdir($target);
        } else {
            unlink($target);
        }
        return ['success' => true];
    }

    public static function emptyTrash($trashDir)
    {
        $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($trashDir, RecursiveDirectoryIterator::SKIP_DOTS));
        $items = [];
        foreach ($rii as $file) {
            $items[] = $file->getPathname();
        }
        // Delete files first, then dirs
        foreach (array_reverse($items) as $item) {
            if (is_dir($item)) rmdir($item);
            else unlink($item);
        }
        return ['success' => true];
    }

    public static function bulkRestoreTrash($trashDir, $baseDir)
    {
        $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($trashDir, RecursiveDirectoryIterator::SKIP_DOTS));
        $items = [];
        foreach ($rii as $file) {
            $rel = ltrim(str_replace($trashDir, '', $file->getPathname()), '/\\');
            $src = $file->getPathname();
            $dst = $baseDir . '/' . $rel;
            if (strpos(realpath(dirname($dst)), $baseDir) === 0) {
                if ($file->isDir()) {
                    if (!is_dir($dst)) mkdir($dst, 0755, true);
                } else {
                    if (!is_dir(dirname($dst))) mkdir(dirname($dst), 0755, true);
                    copy($src, $dst);
                }
            }
            $items[] = $src;
        }
        // After restore, delete from trash
        foreach (array_reverse($items) as $item) {
            if (is_dir($item)) rmdir($item);
            else unlink($item);
        }
        return ['success' => true];
    }
}

class BackupManager
{
    public static function listBackups($backupsDir)
    {
        $backups = [];
        if (!is_dir($backupsDir)) return $backups;

        foreach (glob($backupsDir . '/*', GLOB_ONLYDIR) as $dir) {
            $name = basename($dir);
            $items = [];
            $topLevelItems = scandir($dir);

            foreach ($topLevelItems as $item) {
                if ($item === '.' || $item === '..') continue;
                $fullPath = $dir . DIRECTORY_SEPARATOR . $item;
                $items[] = [
                    'name' => $item,
                    'path' => $item, // Path is relative to the backup dir
                    'type' => is_dir($fullPath) ? 'folder' : 'file'
                ];
            }
            $backups[] = [ 'name' => $name, 'items' => $items ];
        }
        return $backups;
    }

    public static function restoreFromBackup($backupDir, $item, $backupsDir, $baseDir)
    {
        $backupBase = realpath($backupsDir . '/' . $backupDir);
        if (!$backupBase || strpos($backupBase, $backupsDir) !== 0) {
            return ['error' => 'Invalid backup directory'];
        }
        $src = $backupBase . DIRECTORY_SEPARATOR . $item;
        $dst = $baseDir . DIRECTORY_SEPARATOR . $item;
        if (!file_exists($src) || strpos(realpath(dirname($dst)), $baseDir) !== 0) {
            return ['error' => 'Invalid restore path'];
        }
        // Restore logic: copy file or folder recursively
        FileHelper::restoreCopy($src, $dst);
        return ['success' => true];
    }

    public static function deleteBackup($backupDir, $backupsDir)
    {
        $backupBase = realpath($backupsDir . '/' . $backupDir);
        if (!$backupBase || strpos($backupBase, $backupsDir) !== 0) {
            return ['error' => 'Invalid backup directory'];
        }
        $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($backupBase, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($rii as $file) {
            if ($file->isDir()) rmdir($file->getRealPath());
            else unlink($file->getRealPath());
        }
        rmdir($backupBase);
        return ['success' => true];
    }
}

class PresetManager
{
    public static function listPresets($presetsDir)
    {
        $files = glob($presetsDir . '/*.json');
        $presets = [];
        foreach ($files as $file) {
            $name = basename($file, '.json');
            $presets[] = $name;
        }
        return $presets;
    }

    public static function loadPreset($presetsDir, $name)
    {
        $file = $presetsDir . '/' . $name . '.json';
        if (!file_exists($file)) {
            return ['error' => 'Preset not found'];
        }
        $data = file_get_contents($file);
        return $data;
    }

    public static function savePreset($presetsDir, $name, $data)
    {
        if ($name === 'wp-core') {
            return ['error' => 'Cannot overwrite default preset'];
        }
        $file = $presetsDir . '/' . $name . '.json';
        file_put_contents($file, $data);
        return ['success' => true];
    }

    public static function deletePreset($presetsDir, $name)
    {
        if ($name === 'wp-core') {
            return ['error' => 'Cannot delete default preset'];
        }
        $file = $presetsDir . '/' . $name . '.json';
        if (!file_exists($file)) {
            return ['error' => 'Preset not found'];
        }
        unlink($file);
        return ['success' => true];
    }
}

/**
 * Malware Scanner Class
 * Scans .php / .js / .html files for known injection signatures
 */
class MalwareScanner {

    private static $signatures = [
        // ── Specific to the reported sawab-ltd infection ──────────────────
        ['id'=>'sawab_domain',      'type'=>'string', 'severity'=>'critical',
         'pattern'=>'sawab-ltd.com',
         'description'=>'Known malicious domain loader (sawab-ltd.com)'],

        ['id'=>'obf_kgb2tKK',       'type'=>'string', 'severity'=>'critical',
         'pattern'=>'kgb2tKK',
         'description'=>'Obfuscated JS array (kgb2tKK) — sawab injection'],

        ['id'=>'obf_T6Lv6St',       'type'=>'string', 'severity'=>'critical',
         'pattern'=>'T6Lv6St',
         'description'=>'Obfuscated JS function (T6Lv6St) — sawab injection'],

        ['id'=>'obf_MreFnKR',       'type'=>'string', 'severity'=>'critical',
         'pattern'=>'MreFnKR',
         'description'=>'Obfuscated JS variable (MreFnKR) — sawab injection'],

        ['id'=>'obf_CRYj9O',        'type'=>'string', 'severity'=>'critical',
         'pattern'=>'CRYj9O',
         'description'=>'Obfuscated JS variable (CRYj9O) — sawab injection'],

        ['id'=>'litespeed_hook',    'type'=>'string', 'severity'=>'high',
         'pattern'=>'DOMContentLiteSpeedLoaded',
         'description'=>'LiteSpeed event hook used by injection'],

        ['id'=>'litespeed_inject',  'type'=>'regex',  'severity'=>'high',
         'pattern'=>'/type=["\']litespeed\/javascript["\'][^>]*data-src=["\'][^"\']+["\']/',
         'description'=>'LiteSpeed <script> tag injection with external data-src'],

        // ── PHP eval obfuscation ──────────────────────────────────────────
        ['id'=>'eval_base64',       'type'=>'string', 'severity'=>'critical',
         'pattern'=>'eval(base64_decode(',
         'description'=>'PHP eval(base64_decode()) obfuscation'],

        ['id'=>'eval_gzinflate',    'type'=>'string', 'severity'=>'critical',
         'pattern'=>'eval(gzinflate(',
         'description'=>'PHP eval(gzinflate()) obfuscation'],

        ['id'=>'eval_gzuncompress', 'type'=>'string', 'severity'=>'critical',
         'pattern'=>'eval(gzuncompress(',
         'description'=>'PHP eval(gzuncompress()) obfuscation'],

        ['id'=>'eval_strrot13',     'type'=>'string', 'severity'=>'critical',
         'pattern'=>'eval(str_rot13(',
         'description'=>'PHP eval(str_rot13()) obfuscation'],

        ['id'=>'assert_base64',     'type'=>'string', 'severity'=>'critical',
         'pattern'=>'assert(base64_decode(',
         'description'=>'PHP assert(base64_decode()) injection'],

        ['id'=>'eval_file_get',     'type'=>'regex',  'severity'=>'critical',
         'pattern'=>'/eval\s*\(\s*file_get_contents\s*\(/',
         'description'=>'eval(file_get_contents()) — remote dropper'],

        // ── preg_replace /e code execution ───────────────────────────────
        ['id'=>'preg_e',            'type'=>'regex',  'severity'=>'critical',
         'pattern'=>'/preg_replace\s*\(\s*[\'"][^\'"]*\/e[^\'"]*[\'"]\s*,/',
         'description'=>'preg_replace() /e modifier — remote code execution'],

        // ── System commands from user input ───────────────────────────────
        ['id'=>'shell_exec_input',  'type'=>'regex',  'severity'=>'critical',
         'pattern'=>'/shell_exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/',
         'description'=>'shell_exec() called with user-supplied input'],

        ['id'=>'system_input',      'type'=>'regex',  'severity'=>'critical',
         'pattern'=>'/\bsystem\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/',
         'description'=>'system() called with user-supplied input'],

        ['id'=>'passthru_input',    'type'=>'regex',  'severity'=>'critical',
         'pattern'=>'/passthru\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/',
         'description'=>'passthru() called with user-supplied input'],

        ['id'=>'exec_input',        'type'=>'regex',  'severity'=>'critical',
         'pattern'=>'/\bexec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/',
         'description'=>'exec() called with user-supplied input'],

        // ── Known webshell markers ────────────────────────────────────────
        ['id'=>'wso_shell',         'type'=>'string', 'severity'=>'critical',
         'pattern'=>'wso_skin_color',
         'description'=>'Known webshell (WSO)'],

        ['id'=>'filesmanager',      'type'=>'string', 'severity'=>'critical',
         'pattern'=>'$fm_login_user',
         'description'=>'Known webshell (FilesMan)'],

        // ── Large base64 payload ──────────────────────────────────────────
        ['id'=>'large_base64',      'type'=>'regex',  'severity'=>'high',
         'pattern'=>'/[\'"][A-Za-z0-9+\/]{2000,}={0,2}[\'"]/',
         'description'=>'Large base64 string — possible obfuscated payload'],
    ];

    private static $extensions  = ['php','js','html','htm','phtml','shtml'];
    private static $maxFileSize = 5242880; // 5 MB — skip larger files

    /**
     * Scan one file; returns [] if clean, else array of match records.
     */
    public static function scanFile($filePath) {
        $hits = [];
        if (!is_file($filePath) || !is_readable($filePath)) return $hits;
        if (@filesize($filePath) > self::$maxFileSize)      return $hits;

        $content = @file_get_contents($filePath);
        if ($content === false) return $hits;

        $lines      = explode("\n", $content);
        $hitSigIds  = [];

        foreach (self::$signatures as $sig) {
            if (in_array($sig['id'], $hitSigIds)) continue;

            foreach ($lines as $idx => $line) {
                $longLine = strlen($line) > 102400;
                $found    = false;
                $matched  = '';

                if ($sig['type'] === 'string') {
                    if (stripos($line, $sig['pattern']) !== false) {
                        $found   = true;
                        $matched = $sig['pattern'];
                    }
                } elseif (!$longLine && $sig['type'] === 'regex') {
                    if (@preg_match($sig['pattern'], $line, $m)) {
                        $found   = true;
                        $matched = mb_substr($m[0], 0, 120);
                    }
                }

                if ($found) {
                    $hits[] = [
                        'signature_id' => $sig['id'],
                        'description'  => $sig['description'],
                        'severity'     => $sig['severity'],
                        'line_number'  => $idx + 1,
                        'line_preview' => $longLine
                            ? '[Minified/long line — '.number_format(strlen($line)).' chars]'
                            : mb_substr(trim($line), 0, 200),
                        'matched_text' => mb_substr($matched, 0, 120),
                    ];
                    $hitSigIds[] = $sig['id'];
                    break; // one match per signature per file is enough
                }
            }
        }
        return $hits;
    }

    /**
     * Return all scannable file paths under $directory.
     * Excludes WordPress core directories, scan sessions, this script itself, and custom excludes.
     */
    public static function getFilesToScan($directory, $customExcludes = []) {
        $files = [];
        try {
            // Default directories to skip (WordPress core + our own scan sessions)
            $excludeDirs = [
                'wp-admin', 'wp-includes', 'deletion_sessions', 'trash_sessions', 'restore_sessions',
                'scan_sessions', 'db_clean_sessions', 'quarantine',
            ];
            // Merge custom excludes
            if (!empty($customExcludes)) {
                $excludeDirs = array_merge($excludeDirs, $customExcludes);
            }
            $selfPath = realpath(__FILE__);

            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($it as $f) {
                if (!$f->isFile()) continue;
                $path = $f->getPathname();

                // Skip this script itself
                if ($path === $selfPath) continue;

                $ext = strtolower(pathinfo($f->getFilename(), PATHINFO_EXTENSION));
                if (!in_array($ext, self::$extensions)) continue;

                // Skip files > 5 MB
                if ($f->getSize() > 5 * 1024 * 1024) continue;

                // Check if path contains any excluded directory
                $skip = false;
                foreach ($excludeDirs as $exDir) {
                    $needle = DIRECTORY_SEPARATOR . $exDir . DIRECTORY_SEPARATOR;
                    if (strpos($path, $needle) !== false) {
                        $skip = true;
                        break;
                    }
                    // Also match at end of path (last segment)
                    if (substr($path, -strlen($exDir)) === $exDir) {
                        $skip = true;
                        break;
                    }
                }
                if ($skip) continue;

                $files[] = $path;
            }
        } catch (Exception $e) {
            Logger::logError('MalwareScanner::getFilesToScan', ['error' => $e->getMessage()]);
        }
        return $files;
    }
}

/**
 * Database Cleaner Class
 * 
 * Scans and cleans WordPress database bloat: transients, revisions, 
 * orphaned metadata, spam comments, and autoload options.
 * Operates via MySQLi with full safety checks.
 */
class DatabaseCleaner {
    
    private $wpdb;
    private $tablePrefix;

    /**
     * Constructor - initializes database connection
     * 
     * @param string|null $dbFile Optional path to WordPress wp-config.php to extract DB credentials
     * @throws FileOperationException If database connection fails
     */
    public function __construct($dbFile = null) {
        // Try to load WordPress wp-config.php for database credentials
        if ($dbFile === null) {
            $candidates = [
                __DIR__ . '/wp-config.php',
                __DIR__ . '/../wp-config.php',
            ];
            foreach ($candidates as $c) {
                if (file_exists($c)) {
                    $dbFile = $c;
                    break;
                }
            }
        }

        if ($dbFile && file_exists($dbFile)) {
            // Extract DB credentials from wp-config.php
            $content = file_get_contents($dbFile);
            $dbHost     = $this->extractConst($content, 'DB_HOST');
            $dbName     = $this->extractConst($content, 'DB_NAME');
            $dbUser     = $this->extractConst($content, 'DB_USER');
            $dbPass     = $this->extractConst($content, 'DB_PASSWORD');
            $dbPrefix   = $this->extractConst($content, 'TABLE_PREFIX');
            
            if (!$dbHost || !$dbName || !$dbUser) {
                throw new FileOperationException('Could not read database credentials from wp-config.php');
            }
            
            $this->tablePrefix = $dbPrefix ?: 'wp_';
        } else {
            // Fallback: use PHP-defined constants if wp-config.php was loaded elsewhere
            $dbHost = defined('DB_HOST') ? DB_HOST : 'localhost';
            $dbName = defined('DB_NAME') ? DB_NAME : '';
            $dbUser = defined('DB_USER') ? DB_USER : '';
            $dbPass = defined('DB_PASSWORD') ? DB_PASSWORD : '';
            $this->tablePrefix = defined('TABLE_PREFIX') ? TABLE_PREFIX : 'wp_';
            
            if (!$dbName || !$dbUser) {
                throw new FileOperationException('Database configuration not found. Ensure WordPress is properly configured.');
            }
        }

        // Connect via MySQLi using the extracted/local variables
        $this->wpdb = new mysqli($dbHost, $dbUser, $dbPass, $dbName);
        
        if ($this->wpdb->connect_error) {
            throw new FileOperationException('Database connection failed: ' . $this->wpdb->connect_error);
        }
        
        $this->wpdb->set_charset('utf8mb4');
    }
    
    /**
     * Extract a constant value from wp-config.php content
     */
    private function extractConst($content, $name) {
        $pattern = '/define\s*\(\s*[\'"]' . preg_quote($name, '/') . '[\'"]\s*,\s*[\'"]([^\'"]*)[\'"]\s*\)/';
        if (preg_match($pattern, $content, $m)) {
            return $m[1];
        }
        return null;
    }

    /**
     * Wrapper: execute query and return single value
     */
    private function getVar($sql) {
        $result = $this->wpdb->query($sql);
        if (!$result) return null;
        $row = $result->fetch_row();
        return $row ? $row[0] : null;
    }

    /**
     * Wrapper: execute query and return single row as object
     */
    private function getRow($sql) {
        $result = $this->wpdb->query($sql);
        if (!$result) return null;
        return $result->fetch_assoc();
    }

    /**
     * Wrapper: execute query and return all rows as array of objects
     */
    private function getResults($sql) {
        $result = $this->wpdb->query($sql);
        if (!$result) return [];
        $rows = [];
        while ($row = $result->fetch_assoc()) {
            $rows[] = $row;
        }
        return $rows;
    }

    /**
     * Wrapper: execute query and return single column values as array
     */
    private function getCol($sql) {
        $result = $this->wpdb->query($sql);
        if (!$result) return [];
        $cols = [];
        while ($row = $result->fetch_row()) {
            $cols[] = $row[0];
        }
        return $cols;
    }

    /**
     * Wrapper: execute a statement and return affected rows
     */
    private function execute($sql) {
        $this->wpdb->query($sql);
        return $this->wpdb->affected_rows;
    }

    /**
     * Scan database and return counts of cleanable items by category
     */
    public function scan() {
        return [
            'transients'       => $this->countTransients(),
            'site_transients'  => $this->countSiteTransients(),
            'revisions'        => $this->countRevisions(),
            'spam_comments'    => $this->countSpamComments(),
            'trashed_comments' => $this->countTrashedComments(),
            'orphaned_postmeta'=> $this->countOrphanedPostMeta(),
            'orphaned_commentmeta' => $this->countOrphanedCommentMeta(),
            'autoload_options' => $this->countAutoloadOptions(),
            'trashed_posts'    => $this->countTrashedPosts(),
            'malware_posts'    => $this->countMalware('posts'),
            'malware_comments' => $this->countMalware('comments'),
            'malware_options'  => $this->countMalware('options'),
        ];
    }

    /**
     * Common malware patterns to search in database content
     */
    private function getMalwarePatterns() {
        return [
            'sawab-ltd.com', 'kgb2tKK', 'T6Lv6St', 'MreFnKR', 'CRYj9O',
            'eval(base64_decode(', 'eval(gzinflate(', 'eval(gzuncompress(', 'eval(str_rot13(',
            'assert(base64_decode(', 'wso_skin_color', '$fm_login_user',
            'shell_exec($_', 'system($_', 'passthru($_', 'exec($_',
            'data-src="http', 'litespeed\\/javascript',
        ];
    }

    /**
     * Search a table's content column for malware patterns
     */
    private function countMalware($table) {
        $table = $this->tablePrefix . $table;
        $patterns = $this->getMalwarePatterns();
        $conditions = [];
        foreach ($patterns as $p) {
            $escaped = $this->wpdb->real_escape_string($p);
            if ($table === $this->tablePrefix . 'posts') {
                $conditions[] = "({$table}.post_content LIKE '%{$escaped}%' OR {$table}.post_title LIKE '%{$escaped}%')";
            } elseif ($table === $this->tablePrefix . 'comments') {
                $conditions[] = "{$table}.comment_content LIKE '%{$escaped}'";
            } else {
                $conditions[] = "{$table}.option_value LIKE '%{$escaped}'";
            }
        }
        if (empty($conditions)) return 0;
        $sql = "SELECT COUNT(*) FROM {$table} WHERE " . implode(' OR ', $conditions);
        $r = $this->getVar($sql);
        return (int)($r ?: 0);
    }

    /**
     * Get detailed list of items to clean (paginated)
     */
    public function getList($category, $page = 1, $perPage = 50) {
        $offset = ($page - 1) * $perPage;
        switch ($category) {
            case 'transients':
                return $this->getListTransients($offset, $perPage);
            case 'site_transients':
                return $this->getListSiteTransients($offset, $perPage);
            case 'revisions':
                return $this->getListRevisions($offset, $perPage);
            case 'spam_comments':
                return $this->getListSpamComments($offset, $perPage);
            case 'trashed_comments':
                return $this->getListTrashedComments($offset, $perPage);
            case 'orphaned_postmeta':
                return $this->getListOrphanedPostMeta($offset, $perPage);
            case 'orphaned_commentmeta':
                return $this->getListOrphanedCommentMeta($offset, $perPage);
            case 'autoload_options':
                return $this->getListAutoloadOptions($offset, $perPage);
            case 'trashed_posts':
                return $this->getListTrashedPosts($offset, $perPage);
            case 'malware_posts':
                return $this->getListMalware('posts', $offset, $perPage);
            case 'malware_comments':
                return $this->getListMalware('comments', $offset, $perPage);
            case 'malware_options':
                return $this->getListMalware('options', $offset, $perPage);
            default:
                return ['items' => [], 'total' => 0];
        }
    }

    /**
     * Clean (delete) specific items by category and IDs
     */
    public function clean($category, $ids = []) {
        switch ($category) {
            case 'transients':
                return $this->cleanTransients($ids);
            case 'site_transients':
                return $this->cleanSiteTransients($ids);
            case 'revisions':
                return $this->cleanRevisions($ids);
            case 'spam_comments':
                return $this->cleanSpamComments($ids);
            case 'trashed_comments':
                return $this->cleanTrashedComments($ids);
            case 'orphaned_postmeta':
                return $this->cleanOrphanedPostMeta();
            case 'orphaned_commentmeta':
                return $this->cleanOrphanedCommentMeta();
            case 'autoload_options':
                return $this->cleanAutoloadOptions($ids);
            case 'trashed_posts':
                return $this->cleanTrashedPosts($ids);
            case 'malware_posts':
                return $this->cleanMalware('posts', $ids);
            case 'malware_comments':
                return $this->cleanMalware('comments', $ids);
            case 'malware_options':
                return $this->cleanMalware('options', $ids);
            default:
                return ['deleted' => 0, 'error' => 'Unknown category'];
        }
    }

    /**
     * Clean all items in a category at once
     */
    public function cleanAll($category) {
        switch ($category) {
            case 'transients':
                return $this->deleteAllTransients();
            case 'site_transients':
                return $this->deleteAllSiteTransients();
            case 'revisions':
                return $this->deleteAllRevisions();
            case 'spam_comments':
                return $this->deleteAllSpamComments();
            case 'trashed_comments':
                return $this->deleteAllTrashedComments();
            case 'orphaned_postmeta':
                return $this->cleanOrphanedPostMeta();
            case 'orphaned_commentmeta':
                return $this->cleanOrphanedCommentMeta();
            case 'autoload_options':
                return $this->deleteAllAutoloadOptions();
            case 'trashed_posts':
                return $this->deleteAllTrashedPosts();
            case 'malware_posts':
                return $this->deleteAllMalware('posts');
            case 'malware_comments':
                return $this->deleteAllMalware('comments');
            case 'malware_options':
                return $this->deleteAllMalware('options');
            default:
                return ['deleted' => 0, 'error' => 'Unknown category'];
        }
    }

    // ─── TRANSIENTS ────────────────────────────────────────────────
    
    private function countTransients() {
        $key = $this->wpdb->real_escape_string('_transient_');
        $r = $this->getVar("SELECT COUNT(*) FROM {$this->tablePrefix}options WHERE option_name LIKE '{$key}%'");
        return (int)($r ?: 0);
    }

    private function countSiteTransients() {
        $key = $this->wpdb->real_escape_string('_site_transient_');
        $r = $this->getVar("SELECT COUNT(*) FROM {$this->tablePrefix}options WHERE option_name LIKE '{$key}%'");
        return (int)($r ?: 0);
    }

    private function getListTransients($offset, $perPage) {
        $key = $this->wpdb->real_escape_string('_transient_');
        $limit = (int)$perPage;
        $off = (int)$offset;
        $rows = $this->getResults("SELECT option_name, option_value, autoload FROM {$this->tablePrefix}options WHERE option_name LIKE '{$key}%' ORDER BY option_name LIMIT {$limit} OFFSET {$off}");
        return $this->formatTransientRows($rows);
    }

    private function getListSiteTransients($offset, $perPage) {
        $key = $this->wpdb->real_escape_string('_site_transient_');
        $limit = (int)$perPage;
        $off = (int)$offset;
        $rows = $this->getResults("SELECT option_name, option_value, autoload FROM {$this->tablePrefix}options WHERE option_name LIKE '{$key}%' ORDER BY option_name LIMIT {$limit} OFFSET {$off}");
        return $this->formatTransientRows($rows);
    }

    private function formatTransientRows($rows) {
        $items = [];
        foreach ($rows as $row) {
            $name = $row['option_name'];
            $items[] = [
                'id' => $name,
                'name' => htmlspecialchars($name),
                'size_bytes' => strlen($row['option_value'] ?? ''),
                'status' => 'ACTIVE',
                'autoload' => $row['autoload'] ?? 'no',
            ];
        }
        return ['items' => $items, 'total' => $this->countTransients() + $this->countSiteTransients()];
    }

    private function cleanTransients($ids) {
        if (empty($ids)) return ['deleted' => 0];
        $escaped = [];
        foreach ($ids as $id) {
            $escaped[] = "'" . $this->wpdb->real_escape_string($id) . "'";
        }
        $list = implode(',', $escaped);
        $deleted = $this->execute("DELETE FROM {$this->tablePrefix}options WHERE option_name IN ({$list}) AND option_name LIKE '_transient_%'");
        return ['deleted' => $deleted];
    }

    private function cleanSiteTransients($ids) {
        if (empty($ids)) return ['deleted' => 0];
        $escaped = [];
        foreach ($ids as $id) {
            $escaped[] = "'" . $this->wpdb->real_escape_string($id) . "'";
        }
        $list = implode(',', $escaped);
        $deleted = $this->execute("DELETE FROM {$this->tablePrefix}options WHERE option_name IN ({$list}) AND option_name LIKE '_site_transient_%'");
        return ['deleted' => $deleted];
    }

    private function deleteAllTransients() {
        $deleted = $this->execute("DELETE FROM {$this->tablePrefix}options WHERE option_name LIKE '_transient_%'");
        return ['deleted' => $deleted];
    }

    private function deleteAllSiteTransients() {
        $deleted = $this->execute("DELETE FROM {$this->tablePrefix}options WHERE option_name LIKE '_site_transient_%'");
        return ['deleted' => $deleted];
    }

    // ─── REVISIONS ─────────────────────────────────────────────────
    
    private function countRevisions() {
        $r = $this->getVar("SELECT COUNT(*) FROM {$this->tablePrefix}posts WHERE post_type = 'revision'");
        return (int)($r ?: 0);
    }

    private function getListRevisions($offset, $perPage) {
        $limit = (int)$perPage;
        $off = (int)$offset;
        $rows = $this->getResults("SELECT ID, post_title, post_date, post_author FROM {$this->tablePrefix}posts WHERE post_type = 'revision' ORDER BY post_date DESC LIMIT {$limit} OFFSET {$off}");
        $items = [];
        foreach ($rows as $row) {
            $items[] = [
                'id' => (int)$row['ID'],
                'name' => htmlspecialchars($row['post_title'] ?: "Revision #{$row['ID']}"),
                'date' => $row['post_date'],
                'author_id' => (int)$row['post_author'],
                'size_bytes' => 0,
            ];
        }
        return ['items' => $items, 'total' => $this->countRevisions()];
    }

    private function cleanRevisions($ids) {
        if (empty($ids)) return ['deleted' => 0];
        $escaped = [];
        foreach ($ids as $id) {
            $escaped[] = (int)$id;
        }
        $list = implode(',', $escaped);
        $deletedPosts = $this->execute("DELETE FROM {$this->tablePrefix}posts WHERE ID IN ({$list}) AND post_type = 'revision'");
        $deletedMeta = $this->execute("DELETE pm FROM {$this->tablePrefix}postmeta pm INNER JOIN {$this->tablePrefix}posts p ON pm.post_id = p.ID WHERE p.post_type = 'revision' AND p.ID IN ({$list})");
        return ['deleted' => $deletedPosts + $deletedMeta];
    }

    private function deleteAllRevisions() {
        $revIds = $this->getCol("SELECT ID FROM {$this->tablePrefix}posts WHERE post_type = 'revision'");
        if (empty($revIds)) return ['deleted' => 0];
        $escaped = array_map('intval', $revIds);
        $list = implode(',', $escaped);
        $deletedPosts = $this->execute("DELETE FROM {$this->tablePrefix}posts WHERE ID IN ({$list})");
        $deletedMeta = $this->execute("DELETE FROM {$this->tablePrefix}postmeta WHERE post_id IN ({$list})");
        return ['deleted' => $deletedPosts + $deletedMeta];
    }

    private function countSpamComments() {
        $r = $this->getVar("SELECT COUNT(*) FROM {$this->tablePrefix}comments WHERE comment_approved = 'spam'");
        return (int)($r ?: 0);
    }

    private function countTrashedComments() {
        $r = $this->getVar("SELECT COUNT(*) FROM {$this->tablePrefix}comments WHERE comment_approved = 'trash'");
        return (int)($r ?: 0);
    }

    private function getListSpamComments($offset, $perPage) {
        $limit = (int)$perPage;
        $off = (int)$offset;
        $rows = $this->getResults("SELECT comment_ID, comment_author, comment_author_email, comment_date, comment_content FROM {$this->tablePrefix}comments WHERE comment_approved = 'spam' ORDER BY comment_ID DESC LIMIT {$limit} OFFSET {$off}");
        $items = [];
        foreach ($rows as $row) {
            $items[] = [
                'id' => (int)$row['comment_ID'],
                'name' => htmlspecialchars($row['comment_author'] . ' <' . $row['comment_author_email'] . '>'),
                'date' => $row['comment_date'],
                'preview' => htmlspecialchars(mb_substr(strip_tags($row['comment_content']), 0, 100)),
            ];
        }
        return ['items' => $items, 'total' => $this->countSpamComments()];
    }

    private function getListTrashedComments($offset, $perPage) {
        $limit = (int)$perPage;
        $off = (int)$offset;
        $rows = $this->getResults("SELECT comment_ID, comment_author, comment_date FROM {$this->tablePrefix}comments WHERE comment_approved = 'trash' ORDER BY comment_ID DESC LIMIT {$limit} OFFSET {$off}");
        $items = [];
        foreach ($rows as $row) {
            $items[] = [
                'id' => (int)$row['comment_ID'],
                'name' => htmlspecialchars($row['comment_author']),
                'date' => $row['comment_date'],
            ];
        }
        return ['items' => $items, 'total' => $this->countTrashedComments()];
    }

    private function cleanSpamComments($ids) {
        if (empty($ids)) return ['deleted' => 0];
        $escaped = array_map('intval', $ids);
        $list = implode(',', $escaped);
        $del = $this->execute("DELETE FROM {$this->tablePrefix}comments WHERE comment_ID IN ({$list}) AND comment_approved = 'spam'");
        $del += $this->execute("DELETE FROM {$this->tablePrefix}commentmeta WHERE comment_id IN ({$list})");
        return ['deleted' => $del];
    }

    private function cleanTrashedComments($ids) {
        if (empty($ids)) return ['deleted' => 0];
        $escaped = array_map('intval', $ids);
        $list = implode(',', $escaped);
        $del = $this->execute("DELETE FROM {$this->tablePrefix}comments WHERE comment_ID IN ({$list}) AND comment_approved = 'trash'");
        $del += $this->execute("DELETE FROM {$this->tablePrefix}commentmeta WHERE comment_id IN ({$list})");
        return ['deleted' => $del];
    }

    private function deleteAllSpamComments() {
        $ids = $this->getCol("SELECT comment_ID FROM {$this->tablePrefix}comments WHERE comment_approved = 'spam'");
        if (empty($ids)) return ['deleted' => 0];
        $escaped = array_map('intval', $ids);
        $list = implode(',', $escaped);
        $del = $this->execute("DELETE FROM {$this->tablePrefix}comments WHERE comment_ID IN ({$list})");
        $del += $this->execute("DELETE FROM {$this->tablePrefix}commentmeta WHERE comment_id IN ({$list})");
        return ['deleted' => $del];
    }

    private function deleteAllTrashedComments() {
        $ids = $this->getCol("SELECT comment_ID FROM {$this->tablePrefix}comments WHERE comment_approved = 'trash'");
        if (empty($ids)) return ['deleted' => 0];
        $escaped = array_map('intval', $ids);
        $list = implode(',', $escaped);
        $del = $this->execute("DELETE FROM {$this->tablePrefix}comments WHERE comment_ID IN ({$list})");
        $del += $this->execute("DELETE FROM {$this->tablePrefix}commentmeta WHERE comment_id IN ({$list})");
        return ['deleted' => $del];
    }

    private function countOrphanedPostMeta() {
        $sql = "SELECT COUNT(*) FROM {$this->tablePrefix}postmeta pm LEFT JOIN {$this->tablePrefix}posts p ON pm.post_id = p.ID WHERE p.ID IS NULL";
        $r = $this->getVar($sql);
        return (int)($r ?: 0);
    }

    private function countOrphanedCommentMeta() {
        $sql = "SELECT COUNT(*) FROM {$this->tablePrefix}commentmeta cm LEFT JOIN {$this->tablePrefix}comments c ON cm.comment_id = c.comment_ID WHERE c.comment_ID IS NULL";
        $r = $this->getVar($sql);
        return (int)($r ?: 0);
    }

    private function getListOrphanedPostMeta($offset, $perPage) {
        $limit = (int)$perPage;
        $off = (int)$offset;
        $sql = "SELECT pm.meta_id, pm.post_id, pm.meta_key, LENGTH(pm.meta_value) as size_bytes FROM {$this->tablePrefix}postmeta pm LEFT JOIN {$this->tablePrefix}posts p ON pm.post_id = p.ID WHERE p.ID IS NULL ORDER BY pm.meta_id LIMIT {$limit} OFFSET {$off}";
        $rows = $this->getResults($sql);
        $items = [];
        foreach ($rows as $row) {
            $items[] = [
                'id' => (int)$row['meta_id'],
                'name' => "post_id={$row['post_id']}, key=" . htmlspecialchars($row['meta_key']),
                'size_bytes' => (int)$row['size_bytes'],
            ];
        }
        return ['items' => $items, 'total' => $this->countOrphanedPostMeta()];
    }

    private function getListOrphanedCommentMeta($offset, $perPage) {
        $limit = (int)$perPage;
        $off = (int)$offset;
        $sql = "SELECT cm.meta_id, cm.comment_id, cm.meta_key, LENGTH(cm.meta_value) as size_bytes FROM {$this->tablePrefix}commentmeta cm LEFT JOIN {$this->tablePrefix}comments c ON cm.comment_id = c.comment_ID WHERE c.comment_ID IS NULL ORDER BY cm.meta_id LIMIT {$limit} OFFSET {$off}";
        $rows = $this->getResults($sql);
        $items = [];
        foreach ($rows as $row) {
            $items[] = [
                'id' => (int)$row['meta_id'],
                'name' => "comment_id={$row['comment_id']}, key=" . htmlspecialchars($row['meta_key']),
                'size_bytes' => (int)$row['size_bytes'],
            ];
        }
        return ['items' => $items, 'total' => $this->countOrphanedCommentMeta()];
    }

    private function cleanOrphanedPostMeta() {
        $sql = "DELETE pm FROM {$this->tablePrefix}postmeta pm LEFT JOIN {$this->tablePrefix}posts p ON pm.post_id = p.ID WHERE p.ID IS NULL";
        $deleted = $this->execute($sql);
        return ['deleted' => $deleted];
    }

    private function cleanOrphanedCommentMeta() {
        $sql = "DELETE cm FROM {$this->tablePrefix}commentmeta cm LEFT JOIN {$this->tablePrefix}comments c ON cm.comment_id = c.comment_ID WHERE c.comment_ID IS NULL";
        $deleted = $this->execute($sql);
        return ['deleted' => $deleted];
    }

    private function countAutoloadOptions() {
        $r = $this->getVar("SELECT COUNT(*) FROM {$this->tablePrefix}options WHERE autoload = 'yes'");
        return (int)($r ?: 0);
    }

    private function getListAutoloadOptions($offset, $perPage) {
        $limit = (int)$perPage;
        $off = (int)$offset;
        $rows = $this->getResults("SELECT option_name, LENGTH(option_value) as size_bytes, autoload FROM {$this->tablePrefix}options WHERE autoload = 'yes' ORDER BY size_bytes DESC LIMIT {$limit} OFFSET {$off}");
        $items = [];
        foreach ($rows as $row) {
            $items[] = [
                'id' => htmlspecialchars($row['option_name']),
                'name' => htmlspecialchars($row['option_name']),
                'size_bytes' => (int)$row['size_bytes'],
                'autoload' => $row['autoload'],
            ];
        }
        return ['items' => $items, 'total' => $this->countAutoloadOptions()];
    }

    private function cleanAutoloadOptions($ids) {
        if (empty($ids)) return ['deleted' => 0];
        $escaped = [];
        foreach ($ids as $id) {
            $escaped[] = "'" . $this->wpdb->real_escape_string($id) . "'";
        }
        $list = implode(',', $escaped);
        $deleted = $this->execute("DELETE FROM {$this->tablePrefix}options WHERE option_name IN ({$list})");
        return ['deleted' => $deleted];
    }

    private function deleteAllAutoloadOptions() {
        $deleted = $this->execute("DELETE FROM {$this->tablePrefix}options WHERE autoload = 'yes'");
        return ['deleted' => $deleted];
    }

    private function countTrashedPosts() {
        $r = $this->getVar("SELECT COUNT(*) FROM {$this->tablePrefix}posts WHERE post_status = 'trash'");
        return (int)($r ?: 0);
    }

    private function getListTrashedPosts($offset, $perPage) {
        $limit = (int)$perPage;
        $off = (int)$offset;
        $rows = $this->getResults("SELECT ID, post_type, post_title, post_date FROM {$this->tablePrefix}posts WHERE post_status = 'trash' ORDER BY post_date DESC LIMIT {$limit} OFFSET {$off}");
        $items = [];
        foreach ($rows as $row) {
            $items[] = [
                'id' => (int)$row['ID'],
                'name' => htmlspecialchars($row['post_title'] ?: "(Untitled {$row['post_type']})"),
                'type' => $row['post_type'],
                'date' => $row['post_date'],
            ];
        }
        return ['items' => $items, 'total' => $this->countTrashedPosts()];
    }

    private function cleanTrashedPosts($ids) {
        if (empty($ids)) return ['deleted' => 0];
        $escaped = array_map('intval', $ids);
        $list = implode(',', $escaped);
        $del = $this->execute("DELETE FROM {$this->tablePrefix}posts WHERE ID IN ({$list}) AND post_status = 'trash'");
        $del += $this->execute("DELETE FROM {$this->tablePrefix}postmeta WHERE post_id IN ({$list})");
        return ['deleted' => $del];
    }

    private function deleteAllTrashedPosts() {
        $ids = $this->getCol("SELECT ID FROM {$this->tablePrefix}posts WHERE post_status = 'trash'");
        if (empty($ids)) return ['deleted' => 0];
        $escaped = array_map('intval', $ids);
        $list = implode(',', $escaped);
        $del = $this->execute("DELETE FROM {$this->tablePrefix}posts WHERE ID IN ({$list})");
        $del += $this->execute("DELETE FROM {$this->tablePrefix}postmeta WHERE post_id IN ({$list})");
        return ['deleted' => $del];
    }

    // ─── MALWARE IN DATABASE ───────────────────────────────────────

    private function getListMalware($table, $offset, $perPage) {
        $tbl = $this->tablePrefix . $table;
        $patterns = $this->getMalwarePatterns();
        $conditions = [];
        foreach ($patterns as $p) {
            $escaped = $this->wpdb->real_escape_string($p);
            if ($table === 'posts') {
                $conditions[] = "({$tbl}.post_content LIKE '%{$escaped}%' OR {$tbl}.post_title LIKE '%{$escaped}%')";
            } elseif ($table === 'comments') {
                $conditions[] = "({$tbl}.comment_content LIKE '%{$escaped}%')";
            } else { // options
                $conditions[] = "({$tbl}.option_value LIKE '%{$escaped}%')";
            }
        }
        if (empty($conditions)) return ['items' => [], 'total' => 0];
        $where = implode(' OR ', $conditions);
        $limit = (int)$perPage;
        $off = (int)$offset;

        // Build query based on table
        if ($table === 'posts') {
            $sql = "SELECT ID as entry_id, post_title as title, post_type, post_date, LEFT(post_content, 500) as preview FROM {$tbl} WHERE {$where} ORDER BY ID LIMIT {$limit} OFFSET {$off}";
        } elseif ($table === 'comments') {
            $sql = "SELECT comment_ID as entry_id, comment_author as title, comment_approved as type, comment_date, LEFT(comment_content, 500) as preview FROM {$tbl} WHERE {$where} ORDER BY comment_ID LIMIT {$limit} OFFSET {$off}";
        } else { // options
            $sql = "SELECT option_id as entry_id, option_name as title, LENGTH(option_value) as size_bytes, LEFT(option_value, 500) as preview FROM {$tbl} WHERE {$where} ORDER BY option_id LIMIT {$limit} OFFSET {$off}";
        }

        $rows = $this->getResults($sql);
        $items = [];
        foreach ($rows as $row) {
            $id = (int)$row['entry_id'];
            $title = htmlspecialchars($row['title'] ?: "ID: {$id}");
            $extra = '';
            $shortPreview = '';
            $fullContent = '';
            if ($table === 'posts') {
                $extra = "<div style='font-size:.75rem;color:#999;'>Type: {$row['post_type']}</div>";
                $contentClean = strip_tags($row['preview'] ?? '');
                if (!empty($contentClean)) {
                    $shortPreview = '<div style="font-size:.75rem;color:#555;margin-top:3px;max-height:60px;overflow:hidden;">'.htmlspecialchars(mb_substr($contentClean, 0, 200)).'</div>';
                    $fullContent = '<pre style="background:#1e1e1e;color:#d4d4d4;padding:10px;border-radius:6px;font-size:.8rem;max-height:300px;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:0;">'.htmlspecialchars($contentClean).'</pre>';
                }
            } elseif ($table === 'comments') {
                $extra = "<div style='font-size:.75rem;color:#999;'>Status: {$row['type']}</div>";
                $contentClean = strip_tags($row['preview'] ?? '');
                if (!empty($contentClean)) {
                    $shortPreview = '<div style="font-size:.75rem;color:#555;margin-top:3px;max-height:60px;overflow:hidden;">'.htmlspecialchars(mb_substr($contentClean, 0, 200)).'</div>';
                    $fullContent = '<pre style="background:#1e1e1e;color:#d4d4d4;padding:10px;border-radius:6px;font-size:.8rem;max-height:300px;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:0;">'.htmlspecialchars($contentClean).'</pre>';
                }
            } else { // options
                $sz = (int)$row['size_bytes'];
                $units = ['B','KB','MB','GB'];
                $pb = ($sz > 0) ? floor(log($sz)/log(1024)) : 0;
                $pb = min($pb, count($units)-1);
                $extra = "<div style='font-size:.75rem;color:#999;'>Size: ".round($sz/pow(1024,$pb),2).' '.$units[$pb]."</div>";
                $contentClean = strip_tags($row['preview'] ?? '');
                if (!empty($contentClean)) {
                    $shortPreview = '<div style="font-size:.75rem;color:#555;margin-top:3px;max-height:60px;overflow:hidden;">'.htmlspecialchars(mb_substr($contentClean, 0, 200)).'</div>';
                    $fullContent = '<pre style="background:#1e1e1e;color:#d4d4d4;padding:10px;border-radius:6px;font-size:.8rem;max-height:300px;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:0;">'.htmlspecialchars($contentClean).'</pre>';
                }
            }
            $items[] = [
                'id' => $id,
                'name' => $title,
                'date' => $row['post_date'] ?? $row['comment_date'] ?? '',
                'extra' => $extra,
                'preview' => $shortPreview,
                'full_content' => $fullContent,
            ];
        }
        $totalSql = "SELECT COUNT(*) FROM {$tbl} WHERE {$where}";
        $total = (int)($this->getVar($totalSql) ?: 0);
        return ['items' => $items, 'total' => $total];
    }

    private function cleanMalware($table, $ids) {
        if (empty($ids)) return ['deleted' => 0];
        $tbl = $this->tablePrefix . $table;
        $escaped = array_map('intval', $ids);
        $list = implode(',', $escaped);
        if ($table === 'options') {
            $del = $this->execute("DELETE FROM {$tbl} WHERE option_id IN ({$list})");
        } else {
            $idCol = $table === 'posts' ? 'ID' : 'comment_ID';
            $del = $this->execute("DELETE FROM {$tbl} WHERE {$idCol} IN ({$list})");
            if ($table === 'posts') {
                $del += $this->execute("DELETE FROM {$this->tablePrefix}postmeta WHERE post_id IN ({$list})");
            } elseif ($table === 'comments') {
                $del += $this->execute("DELETE FROM {$this->tablePrefix}commentmeta WHERE comment_id IN ({$list})");
            }
        }
        return ['deleted' => $del];
    }

    private function deleteAllMalware($table) {
        $tbl = $this->tablePrefix . $table;
        $patterns = $this->getMalwarePatterns();
        $conditions = [];
        foreach ($patterns as $p) {
            $escaped = $this->wpdb->real_escape_string($p);
            if ($table === 'posts') {
                $conditions[] = "(post_content LIKE '%{$escaped}%' OR post_title LIKE '%{$escaped}%')";
            } elseif ($table === 'comments') {
                $conditions[] = "comment_content LIKE '%{$escaped}'";
            } else {
                $conditions[] = "option_value LIKE '%{$escaped}'";
            }
        }
        if (empty($conditions)) return ['deleted' => 0];
        $where = implode(' OR ', $conditions);
        $del = 0;
        if ($table === 'options') {
            $del = $this->execute("DELETE FROM {$tbl} WHERE {$where}");
        } else {
            $idCol = $table === 'posts' ? 'ID' : 'comment_ID';
            $del = $this->execute("DELETE FROM {$tbl} WHERE {$where}");
            if ($table === 'posts') {
                $subIds = $this->getCol("SELECT ID FROM {$tbl} WHERE {$where}");
                if (!empty($subIds)) {
                    $subList = implode(',', array_map('intval', $subIds));
                    $del += $this->execute("DELETE FROM {$this->tablePrefix}postmeta WHERE post_id IN ({$subList})");
                }
            } elseif ($table === 'comments') {
                $subIds = $this->getCol("SELECT comment_ID FROM {$tbl} WHERE {$where}");
                if (!empty($subIds)) {
                    $subList = implode(',', array_map('intval', $subIds));
                    $del += $this->execute("DELETE FROM {$this->tablePrefix}commentmeta WHERE comment_id IN ({$subList})");
                }
            }
        }
        return ['deleted' => $del];
    }

    /**
     * Close database connection
     */
    public function close() {
        if ($this->wpdb) {
            $this->wpdb->close();
        }
    }
}

/**
 * WordPress Toolkit
 *
 * Groups the "advanced" WordPress operations that talk to the database or the
 * WordPress.org API: safe search-replace, admin user management, database
 * export, and core file integrity checking. Reuses the same wp-config.php
 * credential extraction + MySQLi connection approach as DatabaseCleaner.
 */
class WpToolkit {
    private $wpdb;
    private $tablePrefix;
    private $dbName;
    private $baseDir;

    public function __construct($baseDir = null) {
        $this->baseDir = $baseDir ?: realpath(__DIR__);

        // Resolve wp-config.php (this folder or one level up).
        $dbFile = null;
        foreach ([$this->baseDir . '/wp-config.php', dirname($this->baseDir) . '/wp-config.php'] as $c) {
            if (file_exists($c)) { $dbFile = $c; break; }
        }
        if (!$dbFile) {
            throw new FileOperationException('wp-config.php not found. Ensure this is a WordPress installation.');
        }
        // If found one level up, treat that as the WP root.
        $this->baseDir = realpath(dirname($dbFile));

        $content = file_get_contents($dbFile);
        $dbHost = $this->extractConst($content, 'DB_HOST') ?: 'localhost';
        $dbName = $this->extractConst($content, 'DB_NAME');
        $dbUser = $this->extractConst($content, 'DB_USER');
        $dbPass = $this->extractConst($content, 'DB_PASSWORD');
        $prefix = $this->extractTablePrefix($content);
        if (!$dbName || !$dbUser) {
            throw new FileOperationException('Could not read database credentials from wp-config.php');
        }
        $this->tablePrefix = $prefix ?: 'wp_';
        $this->dbName = $dbName;

        // DB_HOST may contain a :port suffix.
        $port = null;
        if (strpos($dbHost, ':') !== false) {
            list($dbHost, $port) = explode(':', $dbHost, 2);
            $port = is_numeric($port) ? (int)$port : null;
        }
        $this->wpdb = $port
            ? new mysqli($dbHost, $dbUser, $dbPass, $dbName, $port)
            : new mysqli($dbHost, $dbUser, $dbPass, $dbName);
        if ($this->wpdb->connect_error) {
            throw new FileOperationException('Database connection failed: ' . $this->wpdb->connect_error);
        }
        $this->wpdb->set_charset('utf8mb4');
    }

    public function baseDir() { return $this->baseDir; }
    public function prefix() { return $this->tablePrefix; }

    private function extractConst($content, $name) {
        $pattern = '/define\s*\(\s*[\'"]' . preg_quote($name, '/') . '[\'"]\s*,\s*[\'"]([^\'"]*)[\'"]\s*\)/';
        return preg_match($pattern, $content, $m) ? $m[1] : null;
    }

    private function extractTablePrefix($content) {
        // $table_prefix = 'wp_';
        if (preg_match('/\$table_prefix\s*=\s*[\'"]([^\'"]+)[\'"]/', $content, $m)) {
            return $m[1];
        }
        return null;
    }

    private function esc($v) { return $this->wpdb->real_escape_string($v); }

    /* ───────────────────────── SEARCH-REPLACE ───────────────────────── */

    /** All base tables in the current database. */
    public function listTables() {
        $tables = [];
        $res = $this->wpdb->query("SHOW TABLES");
        if ($res) {
            while ($row = $res->fetch_row()) $tables[] = $row[0];
        }
        return $tables;
    }

    /**
     * Recursively walk a value (that may be a PHP-serialized string) applying a
     * str_replace to every scalar, then re-serialize — so serialized arrays/objects
     * stay valid after the replacement. Falls back to a plain replace for
     * non-serialized values.
     */
    public static function recursiveReplace($data, $search, $replace, &$changed) {
        // If it's a serialized string, unserialize, recurse, re-serialize.
        if (is_string($data)) {
            $unser = @unserialize($data);
            if ($unser !== false || $data === 'b:0;') {
                $inner = self::recursiveReplace($unser, $search, $replace, $changed);
                return serialize($inner);
            }
            $new = str_replace($search, $replace, $data);
            if ($new !== $data) $changed = true;
            return $new;
        }
        if (is_array($data)) {
            $out = [];
            foreach ($data as $k => $v) {
                $out[$k] = self::recursiveReplace($v, $search, $replace, $changed);
            }
            return $out;
        }
        if (is_object($data)) {
            foreach ($data as $k => $v) {
                $data->$k = self::recursiveReplace($v, $search, $replace, $changed);
            }
            return $data;
        }
        return $data; // int, float, bool, null — nothing to replace
    }

    /**
     * Process one table for a search-replace pass.
     *
     * @param bool $dryRun When true, count matches but do not write.
     * @return array ['rows_changed'=>int, 'cells_changed'=>int]
     */
    public function searchReplaceTable($table, $search, $replace, $dryRun = true) {
        $rowsChanged = 0;
        $cellsChanged = 0;

        // Identify the primary key(s); fall back to updating by full-row match.
        $pk = [];
        $res = $this->wpdb->query("SHOW KEYS FROM `{$table}` WHERE Key_name = 'PRIMARY'");
        if ($res) {
            while ($row = $res->fetch_assoc()) $pk[] = $row['Column_name'];
        }

        // Get columns.
        $columns = [];
        $res = $this->wpdb->query("SHOW COLUMNS FROM `{$table}`");
        if ($res) {
            while ($row = $res->fetch_assoc()) $columns[] = $row['Field'];
        }
        if (empty($columns)) return ['rows_changed' => 0, 'cells_changed' => 0];

        $result = $this->wpdb->query("SELECT * FROM `{$table}`");
        if (!$result) return ['rows_changed' => 0, 'cells_changed' => 0];

        while ($row = $result->fetch_assoc()) {
            $updates = [];
            foreach ($row as $col => $val) {
                if ($val === null) continue;
                if (strpos($val, $search) === false && !self::maybeSerialized($val)) continue;
                $changed = false;
                $newVal = self::recursiveReplace($val, $search, $replace, $changed);
                if ($changed && $newVal !== $val) {
                    $updates[$col] = $newVal;
                    $cellsChanged++;
                }
            }
            if (!empty($updates)) {
                $rowsChanged++;
                if (!$dryRun && !empty($pk)) {
                    $set = [];
                    foreach ($updates as $col => $newVal) {
                        $set[] = "`{$col}` = '" . $this->esc($newVal) . "'";
                    }
                    $where = [];
                    foreach ($pk as $key) {
                        $where[] = "`{$key}` = '" . $this->esc($row[$key]) . "'";
                    }
                    $this->wpdb->query("UPDATE `{$table}` SET " . implode(', ', $set)
                        . " WHERE " . implode(' AND ', $where) . " LIMIT 1");
                }
            }
        }
        return ['rows_changed' => $rowsChanged, 'cells_changed' => $cellsChanged];
    }

    private static function maybeSerialized($val) {
        return is_string($val) && preg_match('/^(a|O|s|b|i|d):/', $val) === 1;
    }

    /* ───────────────────────── ADMIN USERS ───────────────────────── */

    /** List administrator users. */
    public function listAdmins() {
        $users = $this->tablePrefix . 'users';
        $meta  = $this->tablePrefix . 'usermeta';
        $capKey = $this->tablePrefix . 'capabilities';
        $sql = "SELECT u.ID, u.user_login, u.user_email, u.user_registered
                FROM `{$users}` u
                INNER JOIN `{$meta}` m ON u.ID = m.user_id
                WHERE m.meta_key = '" . $this->esc($capKey) . "'
                  AND m.meta_value LIKE '%administrator%'
                ORDER BY u.ID ASC";
        $res = $this->wpdb->query($sql);
        $out = [];
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $out[] = [
                    'id' => (int)$row['ID'],
                    'login' => $row['user_login'],
                    'email' => $row['user_email'],
                    'registered' => $row['user_registered'],
                ];
            }
        }
        return $out;
    }

    /**
     * Hash a password using WordPress's phpass portable hashing (compatible with
     * wp-includes/class-phpass.php) so the result is accepted by wp-login.php.
     */
    public static function wpHashPassword($password) {
        $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        $salt = '';
        $random = '';
        for ($i = 0; $i < 6; $i++) $random .= chr(random_int(0, 255));
        $count_log2 = 8;
        $setting = '$P$' . $itoa64[$count_log2 + 5];

        $sixbits = function($input) use ($itoa64) {
            $output = '';
            $i = 0;
            $count = strlen($input);
            do {
                $value = ord($input[$i++]);
                $output .= $itoa64[$value & 0x3f];
                if ($i < $count) $value |= ord($input[$i]) << 8;
                $output .= $itoa64[($value >> 6) & 0x3f];
                if ($i++ >= $count) break;
                if ($i < $count) $value |= ord($input[$i]) << 16;
                $output .= $itoa64[($value >> 12) & 0x3f];
                if ($i++ >= $count) break;
                $output .= $itoa64[($value >> 18) & 0x3f];
            } while ($i < $count);
            return $output;
        };

        $setting .= $sixbits(substr($random, 0, 6));
        $salt = substr($setting, 4, 8);
        $count = 1 << $count_log2;
        $hash = md5($salt . $password, true);
        do {
            $hash = md5($hash . $password, true);
        } while (--$count);

        return substr($setting, 0, 12) . $sixbits($hash);
    }

    /** Reset an existing user's password. */
    public function resetPassword($userId, $newPassword) {
        $users = $this->tablePrefix . 'users';
        $hash = self::wpHashPassword($newPassword);
        $userId = (int)$userId;
        $this->wpdb->query("UPDATE `{$users}` SET user_pass = '" . $this->esc($hash)
            . "' WHERE ID = {$userId} LIMIT 1");
        return $this->wpdb->affected_rows >= 0;
    }

    /** Create a brand-new administrator user. */
    public function createAdmin($login, $email, $password) {
        $usersT = $this->tablePrefix . 'users';
        $metaT  = $this->tablePrefix . 'usermeta';

        // Reject duplicate login/email.
        $exists = $this->wpdb->query("SELECT ID FROM `{$usersT}` WHERE user_login = '"
            . $this->esc($login) . "' OR user_email = '" . $this->esc($email) . "' LIMIT 1");
        if ($exists && $exists->num_rows > 0) {
            throw new FileOperationException('A user with that login or email already exists.');
        }

        $hash = self::wpHashPassword($password);
        $now = date('Y-m-d H:i:s');
        $niceName = $this->esc(sanitize_key_fallback($login));
        $this->wpdb->query("INSERT INTO `{$usersT}`
            (user_login, user_pass, user_nicename, user_email, user_registered, user_status, display_name)
            VALUES ('" . $this->esc($login) . "', '" . $this->esc($hash) . "', '{$niceName}', '"
            . $this->esc($email) . "', '{$now}', 0, '" . $this->esc($login) . "')");
        $userId = (int)$this->wpdb->insert_id;
        if ($userId <= 0) {
            throw new FileOperationException('Failed to create user row.');
        }

        // Grant administrator capabilities + user level.
        $capKey = $this->tablePrefix . 'capabilities';
        $levelKey = $this->tablePrefix . 'user_level';
        $caps = 'a:1:{s:13:"administrator";b:1;}';
        $this->wpdb->query("INSERT INTO `{$metaT}` (user_id, meta_key, meta_value)
            VALUES ({$userId}, '" . $this->esc($capKey) . "', '" . $this->esc($caps) . "')");
        $this->wpdb->query("INSERT INTO `{$metaT}` (user_id, meta_key, meta_value)
            VALUES ({$userId}, '" . $this->esc($levelKey) . "', '10')");
        return $userId;
    }

    /* ───────────────────────── CORE INTEGRITY ───────────────────────── */

    /** Read the installed WordPress version from wp-includes/version.php. */
    public function getWpVersion() {
        $verFile = $this->baseDir . '/wp-includes/version.php';
        if (!file_exists($verFile)) return null;
        $content = file_get_contents($verFile);
        if (preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $content, $m)) {
            return $m[1];
        }
        return null;
    }

    /* ───────────────────────── DATABASE EXPORT ───────────────────────── */

    /**
     * Append the SQL dump for a single table to $file (structure + data).
     * Data is written in chunks to stay memory-safe on large tables.
     * Returns the number of rows written.
     */
    public function dumpTableToFile($table, $file) {
        $fh = fopen($file, 'a');
        if (!$fh) throw new FileOperationException('Cannot write export file.');

        fwrite($fh, "\n-- ----------------------------\n");
        fwrite($fh, "-- Table structure for `{$table}`\n");
        fwrite($fh, "-- ----------------------------\n");
        fwrite($fh, "DROP TABLE IF EXISTS `{$table}`;\n");

        $res = $this->wpdb->query("SHOW CREATE TABLE `{$table}`");
        if ($res) {
            $row = $res->fetch_assoc();
            $create = $row['Create Table'] ?? ($row['Create View'] ?? '');
            if ($create) fwrite($fh, $create . ";\n\n");
        }

        // Dump rows in batches.
        $rowCount = 0;
        $offset = 0;
        $batch = 500;
        do {
            $res = $this->wpdb->query("SELECT * FROM `{$table}` LIMIT {$batch} OFFSET {$offset}");
            if (!$res) break;
            $n = $res->num_rows;
            if ($n === 0) break;
            while ($row = $res->fetch_assoc()) {
                $cols = array_map(function($c) { return "`{$c}`"; }, array_keys($row));
                $vals = array_map(function($v) {
                    if ($v === null) return 'NULL';
                    return "'" . $this->wpdb->real_escape_string($v) . "'";
                }, array_values($row));
                fwrite($fh, "INSERT INTO `{$table}` (" . implode(',', $cols) . ") VALUES ("
                    . implode(',', $vals) . ");\n");
                $rowCount++;
            }
            $offset += $batch;
        } while ($n === $batch);

        fwrite($fh, "\n");
        fclose($fh);
        return $rowCount;
    }

    /** Write the export file header once. */
    public function writeExportHeader($file) {
        $header = "-- WordPress Database Export\n"
            . "-- Generated by WordPress Tools Kit on " . date('Y-m-d H:i:s') . "\n"
            . "-- Database: {$this->dbName}\n"
            . "-- Table prefix: {$this->tablePrefix}\n\n"
            . "SET NAMES utf8mb4;\n"
            . "SET FOREIGN_KEY_CHECKS = 0;\n\n";
        file_put_contents($file, $header);
    }

    /** Write the export file footer. */
    public function writeExportFooter($file) {
        file_put_contents($file, "\nSET FOREIGN_KEY_CHECKS = 1;\n", FILE_APPEND);
    }

    public function close() {
        if ($this->wpdb) $this->wpdb->close();
    }
}

/**
 * Minimal fallback for WordPress's sanitize_key(), used when WP core functions
 * are not loaded (this tool runs standalone).
 */
function sanitize_key_fallback($key) {
    $key = strtolower($key);
    return preg_replace('/[^a-z0-9_\-]/', '', $key);
}


/**
 * Delete Controller Class
 * 
 * Main controller that handles all HTTP requests and routes them to appropriate handlers.
 * Provides centralized request processing with security validation and error handling.
 */
class DeleteController {
    private $baseDir;
    private $trashDir;
    private $backupsDir;
    private $presetsDir;

    /**
     * Constructor - Initializes controller with directory paths
     */
    public function __construct() {
        $this->baseDir = realpath(__DIR__);
        $this->trashDir = __DIR__ . '/trash';
        $this->backupsDir = __DIR__ . '/backups';
        $this->presetsDir = __DIR__ . '/presets';
        
        // Ensure required directories exist
        $this->ensureDirectories();
    }
    
    /**
     * Ensures all required directories exist
     */
    private function ensureDirectories() {
        $directories = [
            $this->trashDir,
            $this->backupsDir,
            $this->presetsDir
        ];
        
        foreach ($directories as $dir) {
            if (!is_dir($dir)) {
                if (!mkdir($dir, 0755, true)) {
                    Logger::logError("Failed to create directory", ['directory' => $dir]);
                    throw new FileOperationException("Failed to create directory: $dir");
                }
            }
        }
    }

    /**
     * Main request dispatcher - Routes incoming requests to appropriate handlers
     * 
     * This method analyzes the HTTP request and routes it to the correct handler
     * based on query parameters and HTTP method. It includes security validation
     * and comprehensive error handling.
     */
    public function handleRequest()
    {
        try {
            // Define all available routes with their handlers
        $routes = [
            // Directory and file operations
            ['method' => 'GET',  'param' => 'listdir',              'value' => '1', 'handler' => 'handleListDir'],
            // Deletion operations
            ['method' => 'POST', 'param' => 'start_deletion',       'value' => '1', 'handler' => 'handleStartDeletion'],
            ['method' => 'POST', 'param' => 'process_deletion',     'value' => '1', 'handler' => 'handleProcessDeletion'],
            // Trash operations
            ['method' => 'POST', 'param' => 'start_trash_action',   'value' => '1', 'handler' => 'handleStartTrashAction'],
            ['method' => 'POST', 'param' => 'process_trash_action', 'value' => '1', 'handler' => 'handleProcessTrashAction'],
            ['method' => 'GET',  'param' => 'list_trash',           'value' => '1', 'handler' => 'handleListTrash'],
            ['method' => 'POST', 'param' => 'restore_trash',        'value' => '1', 'handler' => 'handleRestoreTrash'],
            ['method' => 'POST', 'param' => 'delete_trash',         'value' => '1', 'handler' => 'handleDeleteTrash'],
            ['method' => 'POST', 'param' => 'empty_trash',          'value' => '1', 'handler' => 'handleEmptyTrash'],
            ['method' => 'POST', 'param' => 'restore_all_trash',    'value' => '1', 'handler' => 'handleRestoreAllTrash'],
            // Backup operations
            ['method' => 'POST', 'param' => 'restore_backup',       'value' => '1', 'handler' => 'handleRestoreBackup'],
            ['method' => 'POST', 'param' => 'start_restore_backup', 'value' => '1', 'handler' => 'handleStartRestoreBackup'],
            ['method' => 'POST', 'param' => 'process_restore_backup','value' => '1','handler'=>'handleProcessRestoreBackup'],
            ['method' => 'GET',  'param' => 'list_backups',         'value' => '1', 'handler' => 'handleListBackups'],
            ['method' => 'POST', 'param' => 'restore_from_backup',  'value' => '1', 'handler' => 'handleRestoreFromBackup'],
            ['method' => 'POST', 'param' => 'delete_backup',        'value' => '1', 'handler' => 'handleDeleteBackup'],
            // Preset operations
            ['method' => 'GET',  'param' => 'list_presets',         'value' => '1', 'handler' => 'handleListPresets'],
            ['method' => 'GET',  'param' => 'load_preset',          'handler' => 'handleLoadPreset'],
            ['method' => 'POST', 'param' => 'save_preset',          'value' => '1', 'handler' => 'handleSavePreset'],
            ['method' => 'POST', 'param' => 'delete_preset',        'value' => '1', 'handler' => 'handleDeletePreset'],
            // WordPress operations
            ['method' => 'POST', 'param' => 'download_wp',          'value' => '1', 'handler' => 'handleDownloadWordPress'],
            ['method' => 'GET',  'param' => 'list_plugins',         'value' => '1', 'handler' => 'handleListPlugins'],
            ['method' => 'POST', 'param' => 'update_plugins',       'value' => '1', 'handler' => 'handleUpdatePlugins'],
            // ZIP operations
            ['method' => 'POST', 'param' => 'zip_create',           'value' => '1', 'handler' => 'handleZipCreate'],
            ['method' => 'GET',  'param' => 'zip_download',         'value' => '1', 'handler' => 'handleZipDownload'],
            ['method' => 'GET',  'param' => 'list_zips',            'value' => '1', 'handler' => 'handleListZips'],
            ['method' => 'POST', 'param' => 'delete_zip',           'value' => '1', 'handler' => 'handleDeleteZip'],
            ['method' => 'POST', 'param' => 'extract_zip',          'value' => '1', 'handler' => 'handleExtractZip'],
            ['method' => 'POST', 'param' => 'check_extract_path',   'value' => '1', 'handler' => 'handleCheckExtractPath'],
            // File Search & Filtering operations
            ['method' => 'GET',  'param' => 'search_files',         'value' => '1', 'handler' => 'handleSearchFiles'],
            ['method' => 'GET',  'param' => 'filter_files',         'value' => '1', 'handler' => 'handleFilterFiles'],
            // File Permissions operations
            ['method' => 'POST', 'param' => 'set_permissions',      'value' => '1', 'handler' => 'handleSetPermissions'],
            ['method' => 'GET',  'param' => 'get_permissions',      'value' => '1', 'handler' => 'handleGetPermissions'],
            ['method' => 'POST', 'param' => 'fix_wp_permissions',   'value' => '1', 'handler' => 'handleFixWordPressPermissions'],
            // System Health operations
            ['method' => 'GET',  'param' => 'system_health',        'value' => '1', 'handler' => 'handleSystemHealth'],
            // WordPress Security operations
            ['method' => 'POST', 'param' => 'update_wp_salts',      'value' => '1', 'handler' => 'handleUpdateWordPressSalts'],
            // Debug operations
            ['method' => 'GET',  'param' => 'debug_search',         'value' => '1', 'handler' => 'handleDebugSearch'],
            ['method' => 'GET',  'param' => 'test_search',           'value' => '1', 'handler' => 'handleTestSearch'],
            ['method' => 'GET',  'param' => 'check_folder',           'value' => '1', 'handler' => 'handleCheckFolder'],
            ['method' => 'GET',  'param' => 'list_dir',              'value' => '1', 'handler' => 'handleListDir'],
            // Malware scanner routes
            ['method'=>'POST','param'=>'start_scan',              'value'=>'1','handler'=>'handleStartScan'],
            ['method'=>'POST','param'=>'process_scan',             'value'=>'1','handler'=>'handleProcessScan'],
            ['method'=>'POST','param'=>'act_on_malware',           'value'=>'1','handler'=>'handleActOnMalware'],
            ['method'=>'GET', 'param'=>'list_quarantine',          'value'=>'1','handler'=>'handleListQuarantine'],
            ['method'=>'POST','param'=>'empty_quarantine',         'value'=>'1','handler'=>'handleEmptyQuarantine'],
            ['method'=>'POST','param'=>'restore_quarantine',       'value'=>'1','handler'=>'handleRestoreQuarantine'],
            // Command executor
            ['method'=>'POST','param'=>'exec_cmd',                 'value'=>'1','handler'=>'handleExecCmd'],
            // Database cleaner routes
            ['method'=>'GET',  'param'=>'db_scan',                  'value'=>'1','handler'=>'handleDbScan'],
            ['method'=>'GET',  'param'=>'db_get_list',              'value'=>'1','handler'=>'handleDbGetList'],
            ['method'=>'POST','param'=>'db_clean_items',            'value'=>'1','handler'=>'handleDbCleanItems'],
            ['method'=>'POST','param'=>'db_clean_all',              'value'=>'1','handler'=>'handleDbCleanAll'],
            // Search-Replace routes
            ['method'=>'GET',  'param'=>'sr_tables',                'value'=>'1','handler'=>'handleSrTables'],
            ['method'=>'POST','param'=>'sr_start',                 'value'=>'1','handler'=>'handleSrStart'],
            ['method'=>'POST','param'=>'sr_process',               'value'=>'1','handler'=>'handleSrProcess'],
            // Admin user management routes
            ['method'=>'GET',  'param'=>'wp_list_admins',          'value'=>'1','handler'=>'handleWpListAdmins'],
            ['method'=>'POST','param'=>'wp_reset_password',        'value'=>'1','handler'=>'handleWpResetPassword'],
            ['method'=>'POST','param'=>'wp_create_admin',          'value'=>'1','handler'=>'handleWpCreateAdmin'],
            // Database export routes
            ['method'=>'POST','param'=>'db_export_start',          'value'=>'1','handler'=>'handleDbExportStart'],
            ['method'=>'POST','param'=>'db_export_process',        'value'=>'1','handler'=>'handleDbExportProcess'],
            ['method'=>'GET',  'param'=>'db_export_download',      'value'=>'1','handler'=>'handleDbExportDownload'],
            // Core integrity checker routes
            ['method'=>'POST','param'=>'integrity_start',          'value'=>'1','handler'=>'handleIntegrityStart'],
            ['method'=>'POST','param'=>'integrity_process',        'value'=>'1','handler'=>'handleIntegrityProcess'],
            // Misc helpers
            ['method'=>'GET',  'param'=>'detect_wp_root',           'value'=>'1','handler'=>'handleDetectWpRoot'],
        ];

        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
            $requestHandled = false;
            
        foreach ($routes as $route) {
            if ($route['method'] !== $method) {
                continue;
            }
            if (!isset($_REQUEST[$route['param']])) {
                continue;
            }
            if (isset($route['value']) && $_REQUEST[$route['param']] != $route['value']) {
                continue;
            }
                
            // Log the request for audit purposes
            Logger::logAction("Request handled", [
                'method' => $method,
                'param' => $route['param'],
                'handler' => $route['handler'],
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
                
            $this->{$route['handler']}();
                $requestHandled = true;
                break;
            }
            
            // If no route matched, log it
            if (!$requestHandled) {
                Logger::logSecurity("Unhandled request", [
                    'method' => $method,
                    'params' => $_REQUEST,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
            }
            
        } catch (SecurityException $e) {
            Logger::logSecurity("Security violation", [
                'error' => $e->getMessage(),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            SecurityHelper::jsonError($e->getMessage(), 403);
        } catch (Exception $e) {
            Logger::logError("Request handling error", [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            SecurityHelper::jsonError('Internal server error', 500);
        }
    }

    private function handleListDir() {
        $dir = trim($_GET['dir'] ?? '');
        $baseDir = $this->baseDir;
        $targetDir = realpath($baseDir . DIRECTORY_SEPARATOR . $dir);
        
        try {
            if ($targetDir === false || strpos($targetDir, $baseDir) !== 0) {
                HelperUtils::sendErrorResponse('Invalid directory');
            }
                
            $result = [];
            $files = scandir($targetDir);
                
            foreach ($files as $file) {
                if ($file === '.' || $file === '..') continue;
                    
                $fullPath = $targetDir . DIRECTORY_SEPARATOR . $file;
                $fileInfo = HelperUtils::getFileInfo($fullPath, $baseDir);
                    
                $result[] = [
                    'name' => $file,
                    'type' => $fileInfo['type'] === 'directory' ? 'folder' : 'file',
                    'path' => $fileInfo['relativePath'] ?? ltrim(str_replace($baseDir, '', $fullPath), '/\\'),
                    'size' => $fileInfo['size'],
                    'modified' => $fileInfo['modified'],
                    'permissions' => $fileInfo['permissions']
                ];
            }
                
                // Separate directories for the directory browser
                $directories = [];
                foreach ($result as $item) {
                    if ($item['type'] === 'folder') {
                        $directories[] = $item['path'];
                    }
                }
                
                HelperUtils::sendSuccessResponse([
                    'items' => $result, 
                    'directories' => $directories,
                    'dir' => $dir,
                    'count' => count($result)
                ]);
        } catch (Exception $e) {
            HelperUtils::sendErrorResponse('Directory listing failed: ' . $e->getMessage());
        }
    }

    private function handleStartDeletion() {
        $folders = $_POST['folders'] ?? [];
        $files = $_POST['files'] ?? [];
        $doSoftDelete = isset($_POST['softdelete']) && $_POST['softdelete'] == '1';
        $doBackup = isset($_POST['backup']) && $_POST['backup'] == '1';
        $doDryRun = isset($_POST['dryrun']) && $_POST['dryrun'] == '1';
        $backupName = $_POST['backupName'] ?? null;

        if ($doBackup && !$doDryRun) {
            if (empty($backupName)) {
                SecurityHelper::jsonError(['error' => 'Backup name is required.']);
                return;
            }
            // Validate backup name: only allow letters, numbers, underscores, and hyphens.
            if (!preg_match('/^[a-zA-Z0-9_-]+$/', $backupName)) {
                SecurityHelper::jsonError(['error' => 'Invalid backup name. Please use only letters, numbers, underscores, and hyphens.']);
                return;
            }

            $backupDir = $this->backupsDir . '/' . $backupName;
            if (file_exists($backupDir)) {
                SecurityHelper::jsonError(['error' => 'A backup with this name already exists.']);
                return;
            }
            if (!mkdir($backupDir, 0755, true)) {
                SecurityHelper::jsonError(['error' => 'Failed to create backup directory. Please check permissions.']);
                return;
            }

            foreach ($folders as $path) {
                FileHelper::backupItem($this->baseDir . '/' . $path, $backupDir, $path);
            }
            foreach ($files as $path) {
                FileHelper::backupItem($this->baseDir . '/' . $path, $backupDir, $path);
            }
        }

        $items = [];
        foreach ($folders as $f) $items[] = ['type' => 'folder', 'path' => $f];
        foreach ($files as $f) $items[] = ['type' => 'file', 'path' => $f];
        
        $sessionId = SessionManager::startSession('deletion', [
            'items' => $items,
            'done' => [],
            'softdelete' => $doSoftDelete,
            'dryrun' => $doDryRun
        ]);
        SecurityHelper::jsonResponse(['sessionId' => $sessionId, 'total' => count($items)]);
        exit;
    }

    private function handleProcessDeletion() {
        $sessionId = $_POST['sessionId'];

        // Serialize concurrent round-trips on the same session (prevents a
        // double-click / stale poll from processing the same items twice).
        $lock = SessionManager::acquireLock('deletion', $sessionId);
        if ($lock === false) {
            SecurityHelper::jsonResponse(['busy' => true, 'retry' => true]);
            exit;
        }

        try {
            $data = SessionManager::loadSession('deletion', $sessionId);
            if (!$data) {
                SecurityHelper::jsonError(['error' => 'Session not found']);
            }
            $items = $data['items'];
            $done = $data['done'];
            $softdelete = $data['softdelete'];
            $dryrun = $data['dryrun'];
            $results = [];
            $trashDir = __DIR__ . '/trash';
            $baseDir = $this->baseDir;

            if ($softdelete && !$dryrun && !is_dir($trashDir)) {
                mkdir($trashDir, 0755, true);
            }

            // Time-budgeted loop: keep deleting until the request's slice of the
            // server execution cap is used up, then hand control back to the
            // browser which fires the next round-trip. Never a fatal timeout.
            $budget = new JobBudget();
            $processed = 0;
            while (!empty($items) && $budget->hasTime()) {
                $item = array_shift($items);
                $path = $item['path'];
                $resolved = realpath($baseDir . '/' . $path);

                if ($dryrun) {
                    $action = $softdelete ? 'move to trash' : 'permanently delete';
                    $results[$path] = "Would {$action} this {$item['type']}.";
                    $done[] = $item;
                    $processed++;
                    continue;
                }

                if ($item['type'] === 'folder') {
                    if ($resolved && is_dir($resolved)) {
                        if ($softdelete) {
                            $target = $trashDir . '/' . basename($path);
                            rename($resolved, $target);
                            $results[$path] = 'Moved to Trash';
                        } else {
                            $deleteResult = FileHelper::deleteFolder($resolved);
                            $results[$path] = $deleteResult['status'];
                        }
                    } else {
                        $results[$path] = 'Not found';
                    }
                } else { // file
                    if ($resolved && is_file($resolved)) {
                        if ($softdelete) {
                            $target = $trashDir . '/' . basename($path);
                            rename($resolved, $target);
                            $results[$path] = 'Moved to Trash';
                        } else {
                            $results[$path] = unlink($resolved) ? 'Deleted' : 'Failed to delete';
                        }
                    } else {
                        $results[$path] = 'Not found';
                    }
                }
                $done[] = $item;
                $processed++;
            }

            $data['items'] = $items;
            $data['done'] = $done;
            SessionManager::saveSession('deletion', $sessionId, $data);
            $total = count($done) + count($items);
            $progress = $total > 0 ? count($done) / $total : 1;
            $finished = count($items) === 0;
            if ($finished) SessionManager::deleteSession('deletion', $sessionId);
            SecurityHelper::jsonResponse([
                'progress'  => $progress,
                'results'   => $results,
                'finished'  => $finished,
                'processed' => $processed,
                'batchSize' => $budget->nextBatchSize($processed),
            ]);
        } finally {
            SessionManager::releaseLock($lock);
        }
        exit;
    }

    private function handleStartTrashAction() {
        $action = $_POST['action'] ?? '';
        $items = $_POST['items'] ?? [];
        if (!in_array($action, ['restore', 'delete'])) {
            SecurityHelper::jsonError(['error' => 'Invalid action']);
        }
        $sessionId = SessionManager::startSession('trash', [
            'action' => $action,
            'items' => $items,
            'done' => []
        ]);
        SecurityHelper::jsonResponse(['sessionId' => $sessionId, 'total' => count($items)]);
        exit;
    }

    private function handleProcessTrashAction() {
        $sessionId = $_POST['sessionId'];

        $lock = SessionManager::acquireLock('trash', $sessionId);
        if ($lock === false) {
            SecurityHelper::jsonResponse(['busy' => true, 'retry' => true]);
            exit;
        }

        try {
            $data = SessionManager::loadSession('trash', $sessionId);
            if (!$data) {
                SecurityHelper::jsonError(['error' => 'Session not found']);
            }
            $action = $data['action'];
            $items = $data['items'];
            $done = $data['done'];
            $baseDir = $this->baseDir;
            $trashDir = __DIR__ . '/trash';
            $results = [];

            // Time-budgeted loop instead of a fixed batch size.
            $budget = new JobBudget();
            $processed = 0;
            while (!empty($items) && $budget->hasTime()) {
                $rel = array_shift($items);
                $src = $trashDir . '/' . $rel;
                $dst = $baseDir . '/' . $rel;
                if (!file_exists($src) || strpos(realpath($src), $trashDir) !== 0) {
                    $results[$rel] = 'Not found';
                    $done[] = $rel;
                    $processed++;
                    continue;
                }
                if ($action === 'restore') {
                    // First, restore the item by copying it to the destination
                    FileHelper::restoreCopy($src, $dst);

                    // Then, permanently delete the item from the trash
                    if (is_dir($src)) {
                        $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
                        foreach ($rii as $file) {
                            if ($file->isDir()) rmdir($file->getRealPath());
                            else unlink($file->getRealPath());
                        }
                        rmdir($src);
                    } else {
                        unlink($src);
                    }
                    $results[$rel] = 'Restored';
                } else if ($action === 'delete') {
                    if (is_dir($src)) {
                        $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
                        foreach ($rii as $file) {
                            if ($file->isDir()) rmdir($file->getRealPath());
                            else unlink($file->getRealPath());
                        }
                        rmdir($src);
                    } else {
                        unlink($src);
                    }
                    $results[$rel] = 'Deleted';
                }
                $done[] = $rel;
                $processed++;
            }
            $data['items'] = $items;
            $data['done'] = $done;
            SessionManager::saveSession('trash', $sessionId, $data);
            $total = count($done) + count($items);
            $progress = $total > 0 ? count($done) / $total : 1;
            $finished = count($items) === 0;
            if ($finished) SessionManager::deleteSession('trash', $sessionId);
            SecurityHelper::jsonResponse([
                'progress'  => $progress,
                'results'   => $results,
                'finished'  => $finished,
                'processed' => $processed,
                'batchSize' => $budget->nextBatchSize($processed),
            ]);
        } finally {
            SessionManager::releaseLock($lock);
        }
        exit;
    }

    private function handleListTrash() {
        $trashDir = $this->trashDir;
        $items = TrashManager::listTrash($trashDir);
        SecurityHelper::jsonResponse(['items' => $items]);
        exit;
    }

    private function handleRestoreTrash() {
        $rel = $_POST['path'] ?? '';
        $trashDir = $this->trashDir;
        $baseDir = $this->baseDir;
        $result = TrashManager::restoreFromTrash($rel, $trashDir, $baseDir);
        if (isset($result['error'])) {
            SecurityHelper::jsonError($result);
        }
        SecurityHelper::jsonResponse($result);
        exit;
    }

    private function handleDeleteTrash() {
        $rel = $_POST['path'] ?? '';
        $trashDir = $this->trashDir;
        $result = TrashManager::deleteFromTrash($rel, $trashDir);
        if (isset($result['error'])) {
            SecurityHelper::jsonError($result);
        }
        SecurityHelper::jsonResponse($result);
        exit;
    }

    private function handleEmptyTrash() {
        $trashDir = $this->trashDir;
        $result = TrashManager::emptyTrash($trashDir);
        SecurityHelper::jsonResponse($result);
        exit;
    }

    private function handleRestoreAllTrash() {
        $trashDir = $this->trashDir;
        $baseDir = $this->baseDir;
        $result = TrashManager::bulkRestoreTrash($trashDir, $baseDir);
        SecurityHelper::jsonResponse($result);
        exit;
    }

    private function handleRestoreBackup() {
        $backupDir = $_POST['backupDir'] ?? '';
        $item = $_POST['item'] ?? '';
        $baseDir = $this->baseDir;
        $backupBase = realpath(__DIR__ . '/backups/' . $backupDir);
        $backupsDir = realpath(__DIR__ . '/backups');
        
        // If backupBase is false, the directory doesn't exist
        if (!$backupBase) {
            SecurityHelper::jsonError('Backup directory does not exist: ' . $backupDir);
        }
        
        // Security check - ensure backup is within backups directory
        if (!$backupsDir || strpos($backupBase, $backupsDir) !== 0) {
            Logger::logDebug('backup_security_violation', [
                'backupDir' => $backupDir,
                'backupBase' => $backupBase ?? 'null',
                'backupsDir' => $backupsDir
            ]);
            SecurityHelper::jsonError('Backup directory does not exist or is invalid: ' . $backupDir);
        }
        $src = $backupBase . DIRECTORY_SEPARATOR . basename($item);
        $dst = $baseDir . DIRECTORY_SEPARATOR . $item;
        if (!file_exists($src) || strpos(realpath($src), $backupBase) !== 0 || strpos(realpath(dirname($dst)), $baseDir) !== 0) {
            SecurityHelper::jsonError('Invalid restore path');
        }
        FileHelper::restoreCopy($src, $dst);
        SecurityHelper::jsonResponse(['success' => true]);
        exit;
    }

    private function handleStartRestoreBackup() {
        $backupsDir = $this->backupsDir;
        $backupDir = $_POST['backupDir'] ?? '';
        $items = $_POST['items'] ?? [];
        $backupBase = realpath($backupsDir . '/' . $backupDir);
        $baseDir = $this->baseDir;
        if (!$backupBase || strpos($backupBase, $backupsDir) !== 0) {
            Logger::logDebug('backup_operation_failed', [
            'backupDir' => $backupDir,
            'backupsDir' => $backupsDir,
            'backupBase' => $backupBase ?? 'null',
            'operation' => 'restore'
        ]);
        SecurityHelper::jsonError('Backup directory does not exist or is invalid: ' . $backupDir);
        }
        if (!is_array($items) || empty($items)) {
            SecurityHelper::jsonError('No items specified');
        }
        $sessionId = SessionManager::startSession('restore', [
            'backupDir' => $backupDir,
            'items' => $items,
            'done' => []
        ]);
        SecurityHelper::jsonResponse(['sessionId' => $sessionId, 'total' => count($items)]);
        exit;
    }

    private function handleProcessRestoreBackup() {
        $backupsDir = $this->backupsDir;
        $sessionId = $_POST['sessionId'];

        $lock = SessionManager::acquireLock('restore', $sessionId);
        if ($lock === false) {
            SecurityHelper::jsonResponse(['busy' => true, 'retry' => true]);
            exit;
        }

        try {
            $data = SessionManager::loadSession('restore', $sessionId);
            if (!$data) {
                SecurityHelper::jsonError(['error' => 'Session not found']);
            }
            $backupDir = $data['backupDir'];
            $backupBase = realpath($backupsDir . '/' . $backupDir);
            $baseDir = $this->baseDir;
            $items = $data['items'];
            $done = $data['done'];
            $results = [];

            // Time-budgeted loop instead of a fixed batch size.
            $budget = new JobBudget();
            $processed = 0;
            while (!empty($items) && $budget->hasTime()) {
                $rel = array_shift($items);
                $src = $backupBase . '/' . $rel;
                $dst = $baseDir . '/' . $rel;
                if (!file_exists($src) || strpos(realpath(dirname($dst)), $baseDir) !== 0) {
                    $results[$rel] = 'Not found or invalid path';
                    $done[] = $rel;
                    $processed++;
                    continue;
                }
                $restoreResult = true;
                $restoreError = '';
                $restoreCopy = function($src, $dst) use (&$restoreCopy, &$restoreResult, &$restoreError) {
                    if (is_dir($src)) {
                        if (!is_dir($dst)) {
                            if (!mkdir($dst, 0755, true)) {
                                $restoreResult = false;
                                $restoreError = 'Failed to create directory: ' . $dst;
                                return;
                            }
                        }
                        $entries = scandir($src);
                        foreach ($entries as $entry) {
                            if ($entry === '.' || $entry === '..') continue;
                            $restoreCopy($src . '/' . $entry, $dst . '/' . $entry);
                            if (!$restoreResult) return;
                        }
                    } else {
                        if (!copy($src, $dst)) {
                            $restoreResult = false;
                            $restoreError = 'Failed to copy file: ' . $src;
                        }
                    }
                };
                $restoreCopy($src, $dst);
                if ($restoreResult) {
                    $results[$rel] = 'Restored';
                } else {
                    $results[$rel] = 'Failed: ' . $restoreError;
                }
                $done[] = $rel;
                $processed++;
            }
            $data['items'] = $items;
            $data['done'] = $done;
            SessionManager::saveSession('restore', $sessionId, $data);
            $total = count($done) + count($items);
            $progress = $total > 0 ? count($done) / $total : 1;
            $finished = count($items) === 0;
            if ($finished) SessionManager::deleteSession('restore', $sessionId);
            SecurityHelper::jsonResponse([
                'progress'  => $progress,
                'results'   => $results,
                'finished'  => $finished,
                'processed' => $processed,
                'batchSize' => $budget->nextBatchSize($processed),
            ]);
        } finally {
            SessionManager::releaseLock($lock);
        }
        exit;
    }

    private function handleListBackups() {
        $backupsDir = $this->backupsDir;
        $backups = BackupManager::listBackups($backupsDir);
        SecurityHelper::jsonResponse(['backups' => $backups]);
        exit;
    }

    private function handleRestoreFromBackup() {
        $backupsDir = $this->backupsDir;
        $baseDir = $this->baseDir;
        $backupDir = $_POST['backupDir'] ?? '';
        $item = $_POST['item'] ?? '';
        
        // Check if backups directory exists
        if (!is_dir($backupsDir)) {
            Logger::logDebug('backups_directory_missing', ['backupsDir' => $backupsDir]);
            SecurityHelper::jsonError('Backups directory does not exist: ' . $backupsDir);
        }
        
        // Add debugging for backup restore operations
        Logger::logDebug('backup_restore_attempt', [
            'backupDir' => $backupDir,
            'item' => $item,
            'backupsDir' => $backupsDir,
            'baseDir' => $baseDir,
            'backupsDirExists' => is_dir($backupsDir),
            'backupPathExists' => is_dir($backupsDir . '/' . $backupDir)
        ]);
        
        $result = BackupManager::restoreFromBackup($backupDir, $item, $backupsDir, $baseDir);
        if (isset($result['error'])) {
            Logger::logDebug('backup_restore_failed', [
                'error' => $result['error'],
                'backupDir' => $backupDir,
                'item' => $item
            ]);
            SecurityHelper::jsonError($result['error']);
        }
        SecurityHelper::jsonResponse($result);
        exit;
    }

    private function handleDeleteBackup() {
        $backupsDir = $this->backupsDir;
        $backupDir = $_POST['backupDir'] ?? '';
        
        // Check if backups directory exists
        if (!is_dir($backupsDir)) {
            Logger::logDebug('backups_directory_missing', ['backupsDir' => $backupsDir]);
            SecurityHelper::jsonError('Backups directory does not exist: ' . $backupsDir);
        }
        
        // Add debugging for backup delete operations
        Logger::logDebug('backup_delete_attempt', [
            'backupDir' => $backupDir,
            'backupsDir' => $backupsDir,
            'backupsDirExists' => is_dir($backupsDir),
            'backupPathExists' => is_dir($backupsDir . '/' . $backupDir)
        ]);
        
        $result = BackupManager::deleteBackup($backupDir, $backupsDir);
        if (isset($result['error'])) {
            Logger::logDebug('backup_delete_failed', [
                'error' => $result['error'],
                'backupDir' => $backupDir
            ]);
            SecurityHelper::jsonError($result['error']);
        }
        SecurityHelper::jsonResponse($result);
        exit;
    }

    private function handleListPresets() {
        $presetsDir = $this->presetsDir;
        $presets = PresetManager::listPresets($presetsDir);
        SecurityHelper::jsonResponse(['presets' => $presets]);
        exit;
    }

    private function handleLoadPreset() {
        $presetsDir = $this->presetsDir;
        $name = preg_replace('/[^a-zA-Z0-9_\-]/', '', $_GET['load_preset']);
        $data = PresetManager::loadPreset($presetsDir, $name);
        if (is_array($data) && isset($data['error'])) {
            SecurityHelper::jsonError($data);
        }
        SecurityHelper::jsonResponse($data);
        exit;
    }

    private function handleSavePreset() {
        $presetsDir = $this->presetsDir;
        $name = preg_replace('/[^a-zA-Z0-9_\-]/', '', $_POST['name'] ?? '');
        if (!$name) {
            SecurityHelper::jsonError('Invalid preset name');
        }
        $data = $_POST['data'] ?? '';
        if (!$data) {
            SecurityHelper::jsonError('No data provided');
        }
        $result = PresetManager::savePreset($presetsDir, $name, $data);
        SecurityHelper::jsonResponse($result);
        exit;
    }

    private function handleDeletePreset() {
        $presetsDir = $this->presetsDir;
        $name = preg_replace('/[^a-zA-Z0-9_\-]/', '', $_POST['name'] ?? '');
        $result = PresetManager::deletePreset($presetsDir, $name);
        if (isset($result['error'])) {
            SecurityHelper::jsonError($result);
        }
        SecurityHelper::jsonResponse($result);
        exit;
    }

    private function handleDownloadWordPress() {
        if (!class_exists('ZipArchive')) {
            SecurityHelper::jsonError('The ZipArchive class is not installed or enabled in your PHP configuration, which is required for this function.');
            return;
        }
        Logger::logDebug('handleDownloadWordPress started');
        try {
            $baseDir = realpath(__DIR__);
            $extraDir = $baseDir . '/tempextra';
            $wpZip = $baseDir . '/latest.zip';
            $preparedZip = $baseDir . '/prepared_wp.zip';
            
            // Check directory permissions
            if (!is_writable($baseDir)) {
                throw new Exception('Directory is not writable: ' . $baseDir);
            }
            
            // Clean up any previous runs
            if (file_exists($wpZip)) {
                if (!unlink($wpZip)) {
                    throw new Exception('Failed to delete existing zip file: ' . $wpZip);
                }
            }
            if (file_exists($preparedZip)) {
                if (!unlink($preparedZip)) {
                    throw new Exception('Failed to delete existing prepared zip: ' . $preparedZip);
                }
            }
            if (is_dir($extraDir)) {
                $it = new RecursiveDirectoryIterator($extraDir, RecursiveDirectoryIterator::SKIP_DOTS);
                $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
                foreach($files as $file) {
                    if ($file->isDir()) {
                        if (!rmdir($file->getRealPath())) {
                            throw new Exception('Failed to remove directory: ' . $file->getRealPath());
                        }
                    } else {
                        if (!unlink($file->getRealPath())) {
                            throw new Exception('Failed to remove file: ' . $file->getRealPath());
                        }
                    }
                }
                if (!rmdir($extraDir)) {
                    throw new Exception('Failed to remove extra directory: ' . $extraDir);
                }
            }
            
            // Create temp directory
            if (!mkdir($extraDir, 0755, true)) {
                throw new Exception('Failed to create temp directory: ' . $extraDir);
            }
            
            // Download latest.zip
            $wpUrl = 'https://wordpress.org/latest.zip';
            $context = stream_context_create([
                'http' => [
                    'timeout' => 300,
                    'user_agent' => 'WordPress Tools Kit'
                ]
            ]);
            $wpData = file_get_contents($wpUrl, false, $context);
            if ($wpData === false) {
                throw new Exception('Failed to download WordPress from: ' . $wpUrl);
            }
            
            if (file_put_contents($wpZip, $wpData) === false) {
                throw new Exception('Failed to save downloaded WordPress zip');
            }
            
            // Extract to extraDir
            $zip = new ZipArchive();
            if ($zip->open($wpZip) !== true) {
                throw new Exception('Failed to open downloaded zip: ' . $zip->getStatusString());
            }
            
            if (!$zip->extractTo($extraDir)) {
                throw new Exception('Failed to extract WordPress zip');
            }
            $zip->close();
            
            // Check if wordpress directory exists
            $wordpressDir = $extraDir . '/wordpress';
            if (!is_dir($wordpressDir)) {
                throw new Exception('WordPress directory not found in extracted files');
            }
            
            // Delete wp-content
            $wpContent = $wordpressDir . '/wp-content';
            if (is_dir($wpContent)) {
                $it = new RecursiveDirectoryIterator($wpContent, RecursiveDirectoryIterator::SKIP_DOTS);
                $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
                foreach($files as $file) {
                    if ($file->isDir()) {
                        if (!rmdir($file->getRealPath())) {
                            throw new Exception('Failed to remove wp-content directory: ' . $file->getRealPath());
                        }
                    } else {
                        if (!unlink($file->getRealPath())) {
                            throw new Exception('Failed to remove wp-content file: ' . $file->getRealPath());
                        }
                    }
                }
                if (!rmdir($wpContent)) {
                    throw new Exception('Failed to remove wp-content directory');
                }
            }
            
            // Re-zip the remaining wordpress folder
            $zip = new ZipArchive();
            if ($zip->open($preparedZip, ZipArchive::CREATE) !== true) {
                throw new Exception('Failed to create prepared zip: ' . $zip->getStatusString());
            }
            
            $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($wordpressDir, RecursiveDirectoryIterator::SKIP_DOTS));
            foreach ($files as $file) {
                $filePath = $file->getRealPath();
                $localPath = substr($filePath, strlen($wordpressDir) + 1);
                if ($file->isDir()) {
                    if (!$zip->addEmptyDir($localPath)) {
                        throw new Exception('Failed to add directory to zip: ' . $localPath);
                    }
                } else {
                    if (!$zip->addFile($filePath, $localPath)) {
                        throw new Exception('Failed to add file to zip: ' . $localPath);
                    }
                }
            }
            $zip->close();
            
            // Extract prepared zip to baseDir
            $zip = new ZipArchive();
            if ($zip->open($preparedZip) !== true) {
                throw new Exception('Failed to open prepared zip for extraction: ' . $zip->getStatusString());
            }
            
            if (!$zip->extractTo($baseDir)) {
                throw new Exception('Failed to extract prepared zip to base directory');
            }
            $zip->close();
            
            // Clean up
            if (file_exists($wpZip) && !unlink($wpZip)) {
                Logger::logDebug('Warning: Failed to clean up wpZip: ' . $wpZip);
            }
            if (file_exists($preparedZip) && !unlink($preparedZip)) {
                Logger::logDebug('Warning: Failed to clean up preparedZip: ' . $preparedZip);
            }
            
            if (is_dir($extraDir)) {
                $it = new RecursiveDirectoryIterator($extraDir, RecursiveDirectoryIterator::SKIP_DOTS);
                $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
                foreach($files as $file) {
                    if ($file->isDir()) {
                        @rmdir($file->getRealPath());
                    } else {
                        @unlink($file->getRealPath());
                    }
                }
                @rmdir($extraDir);
            }
            
            Logger::logAction('WordPress core files replaced successfully');
            SecurityHelper::jsonResponse(['success' => true, 'message' => 'WordPress core files replaced successfully']);
        } catch (Throwable $e) {
            Logger::logDebug('WordPress download error: ' . $e->getMessage());
            SecurityHelper::jsonError('WordPress download failed: ' . $e->getMessage());
        }
        exit;
    }

    private function handleListPlugins() {
        $baseDir = realpath(__DIR__);
        $pluginsDir = $baseDir . '/wp-content/plugins';
        $plugins = [];
        if (is_dir($pluginsDir)) {
            foreach (scandir($pluginsDir) as $item) {
                if ($item === '.' || $item === '..') continue;
                $path = $pluginsDir . '/' . $item;
                if (is_dir($path)) {
                    // Check if exists in WordPress.org repo
                    $apiUrl = 'https://api.wordpress.org/plugins/info/1.0/' . urlencode($item) . '.json';
                    $json = @file_get_contents($apiUrl);
                    if ($json && ($info = json_decode($json, true)) && isset($info['download_link'])) {
                        $plugins[] = [
                            'slug' => $item,
                            'name' => isset($info['name']) ? $info['name'] : $item,
                            'author' => isset($info['author']) ? strip_tags($info['author']) : ''
                        ];
                    }
                }
            }
        }
        SecurityHelper::jsonResponse(['plugins' => $plugins]);
        exit;
    }

    private function handleUpdatePlugins() {
        $baseDir = realpath(__DIR__);
        $pluginsDir = $baseDir . '/wp-content/plugins';
        $input = json_decode(file_get_contents('php://input'), true);
        $slugs = isset($input['slugs']) && is_array($input['slugs']) ? $input['slugs'] : [];
        $results = [];
        foreach ($slugs as $slug) {
            $result = [ 'status' => '', 'error' => '' ];
            $apiUrl = 'https://api.wordpress.org/plugins/info/1.0/' . urlencode($slug) . '.json';
            $json = @file_get_contents($apiUrl);
            $info = $json ? json_decode($json, true) : null;
            if (!$info || !isset($info['download_link'])) {
                $result['status'] = 'Failed';
                $result['error'] = 'Not found in WordPress.org';
                $results[$slug] = $result;
                continue;
            }
            $downloadUrl = $info['download_link'];
            $zipFile = $baseDir . '/plugin_tmp_' . $slug . '.zip';
            $tmpDir = $baseDir . '/plugin_tmp_' . $slug;
            // Clean up any previous
            if (file_exists($zipFile)) unlink($zipFile);
            if (is_dir($tmpDir)) {
                $it = new RecursiveDirectoryIterator($tmpDir, RecursiveDirectoryIterator::SKIP_DOTS);
                $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
                foreach($files as $file) {
                    if ($file->isDir()) rmdir($file->getRealPath());
                    else unlink($file->getRealPath());
                }
                rmdir($tmpDir);
            }
            // Download zip
            $zipData = @file_get_contents($downloadUrl);
            if ($zipData === false) {
                $result['status'] = 'Failed';
                $result['error'] = 'Download failed';
                $results[$slug] = $result;
                continue;
            }
            file_put_contents($zipFile, $zipData);
            // Extract zip
            $zip = new ZipArchive();
            if ($zip->open($zipFile) !== true) {
                $result['status'] = 'Failed';
                $result['error'] = 'Zip open failed';
                unlink($zipFile);
                $results[$slug] = $result;
                continue;
            }
            $zip->extractTo($tmpDir);
            $zip->close();
            unlink($zipFile);
            // Find plugin folder in extracted (should be $slug or first dir)
            $pluginExtractedDir = $tmpDir . '/' . $slug;
            if (!is_dir($pluginExtractedDir)) {
                // Try to find first dir
                $dirs = array_filter(glob($tmpDir . '/*'), 'is_dir');
                $pluginExtractedDir = count($dirs) > 0 ? reset($dirs) : null;
            }
            if (!$pluginExtractedDir || !is_dir($pluginExtractedDir)) {
                $result['status'] = 'Failed';
                $result['error'] = 'Extracted plugin folder not found';
                // Clean up
                $it = new RecursiveDirectoryIterator($tmpDir, RecursiveDirectoryIterator::SKIP_DOTS);
                $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
                foreach($files as $file) {
                    if ($file->isDir()) rmdir($file->getRealPath());
                    else unlink($file->getRealPath());
                }
                rmdir($tmpDir);
                $results[$slug] = $result;
                continue;
            }
            // Remove old plugin folder
            $targetDir = $pluginsDir . '/' . $slug;
            if (is_dir($targetDir)) {
                $it = new RecursiveDirectoryIterator($targetDir, RecursiveDirectoryIterator::SKIP_DOTS);
                $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
                foreach($files as $file) {
                    if ($file->isDir()) rmdir($file->getRealPath());
                    else unlink($file->getRealPath());
                }
                rmdir($targetDir);
            }
            // Move new plugin folder in place
            rename($pluginExtractedDir, $targetDir);
            // Clean up temp
            if (is_dir($tmpDir)) {
                $it = new RecursiveDirectoryIterator($tmpDir, RecursiveDirectoryIterator::SKIP_DOTS);
                $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
                foreach($files as $file) {
                    if ($file->isDir()) rmdir($file->getRealPath());
                    else unlink($file->getRealPath());
                }
                rmdir($tmpDir);
            }
            $result['status'] = 'Updated';
            $results[$slug] = $result;
        }
        SecurityHelper::jsonResponse(['results' => $results]);
        exit;
    }
    
    /**
     * Handles ZIP file creation from selected files and folders
     */
    private function handleZipCreate() {
        $items = $_POST['items'] ?? [];
        $zipName = $_POST['zipName'] ?? 'archive_' . date('Ymd_His') . '.zip';
        $zipName = basename($zipName); // Sanitize

        Logger::logDebug('zip_create: received items=' . json_encode($items));
        
        if (!is_array($items) || empty($items)) {
            SecurityHelper::jsonError('No items specified');
        }
        
        $baseDir = realpath(__DIR__);
        $zipDir = __DIR__ . '/zips';
        $zipPath = $zipDir . '/' . $zipName;
        
        if (!is_dir($zipDir)) {
            mkdir($zipDir, 0755, true);
        }

        // If file exists, add timestamp to make it unique
        $originalZipName = $zipName;
        $counter = 1;
        while (file_exists($zipPath)) {
            $nameWithoutExt = pathinfo($originalZipName, PATHINFO_FILENAME);
            $extension = pathinfo($originalZipName, PATHINFO_EXTENSION);
            $zipName = $nameWithoutExt . '_' . date('Ymd_His') . '_' . $counter . '.' . $extension;
            $zipPath = $zipDir . '/' . $zipName;
            $counter++;
            
            // Prevent infinite loop
            if ($counter > 100) {
                SecurityHelper::jsonError('Unable to create unique filename. Please try a different name.');
            }
        }

        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
            Logger::logDebug('zip_create: zip->open failed for path=' . $zipPath);
            SecurityHelper::jsonError('Failed to create zip file');
        }
        
        foreach ($items as $rel) {
            $rel = ltrim($rel, '/\\');
            $abs = realpath($baseDir . DIRECTORY_SEPARATOR . $rel);
            if ($abs === false || strpos($abs, $baseDir) !== 0) continue;
            
            if (is_dir($abs)) {
                $files = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($abs, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );
            foreach ($files as $file) {
                    $filePath = $file->getRealPath();
                    $localPath = $rel . '/' . ltrim(str_replace($abs, '', $filePath), '/\\');
                    if ($file->isDir()) {
                        $zip->addEmptyDir($localPath);
                    } else {
                        $zip->addFile($filePath, $localPath);
                    }
                }
            } elseif (is_file($abs)) {
                $zip->addFile($abs, $rel);
            }
        }
        
        $zip->close();
        Logger::logDebug('zip_create: zip closed, exists=' . (file_exists($zipPath) ? 'yes' : 'no'));
        
        if (!file_exists($zipPath)) {
            SecurityHelper::jsonError('Zip file was not created.');
        }
        
        $response = [
            'zip' => 'zips/' . $zipName,
            'download_url' => $_SERVER['PHP_SELF'] . '?zip_download=1&file=' . urlencode($zipName)
        ];
        
        // If filename was changed, inform the user
        if (isset($originalZipName) && $originalZipName !== $zipName) {
            $response['original_name'] = $originalZipName;
            $response['new_name'] = $zipName;
            $response['name_changed'] = true;
        }
        
        SecurityHelper::jsonResponse($response);
            exit;
        }
    
    /**
     * Handles ZIP file download
     */
    private function handleZipDownload() {
        $zipName = basename($_GET['file']);
        $zipPath = __DIR__ . '/zips/' . $zipName;
        
        if (!file_exists($zipPath) || strpos(realpath($zipPath), realpath(__DIR__ . '/zips')) !== 0) {
            http_response_code(404);
            echo 'File not found.';
            exit;
        }
        
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . $zipName . '"');
        header('Content-Length: ' . filesize($zipPath));
        readfile($zipPath);
            exit;
        }
    
    /**
     * Lists available ZIP files
     */
    private function handleListZips() {
        $zipDir = __DIR__ . '/zips';
        $zips = [];
        
        if (is_dir($zipDir)) {
            foreach (glob($zipDir . '/*.zip') as $file) {
                $name = basename($file);
                $zips[] = [
                    'name' => $name,
                    'download_url' => $_SERVER['PHP_SELF'] . '?zip_download=1&file=' . urlencode($name)
                ];
            }
        }
        
        SecurityHelper::jsonResponse(['zips' => $zips]);
            exit;
        }

    /**
     * Deletes a ZIP file
     */
    private function handleDeleteZip() {
        $zipName = basename($_POST['zipName'] ?? '');
        $zipPath = __DIR__ . '/zips/' . $zipName;
        
        if (!file_exists($zipPath) || strpos(realpath($zipPath), realpath(__DIR__ . '/zips')) !== 0) {
            SecurityHelper::jsonError('ZIP file not found or invalid path.');
        }
        
        if (unlink($zipPath)) {
            Logger::logAction('zip_delete', ['file' => $zipName]);
            SecurityHelper::jsonResponse(['success' => true, 'message' => 'ZIP file deleted successfully.']);
        } else {
            SecurityHelper::jsonError('Failed to delete ZIP file.');
        }
    }

    /**
     * Extracts a ZIP file to specified location
     */
    private function handleExtractZip() {
        $zipName = basename($_POST['zipName'] ?? '');
        $extractPath = $_POST['extractPath'] ?? '';
        $mode = $_POST['mode'] ?? 'new'; // new, overwrite, merge, empty
        $zipPath = __DIR__ . '/zips/' . $zipName;
        
        if (!file_exists($zipPath) || strpos(realpath($zipPath), realpath(__DIR__ . '/zips')) !== 0) {
            SecurityHelper::jsonError('ZIP file not found or invalid path.');
        }
        
        // Validate extract path - allow empty for root directory
        $extractPath = trim($extractPath, '/\\');
        // Empty path means extract to root directory
        
        // Log the extraction attempt for debugging
        Logger::logDebug('zip_extract_attempt', [
            'zipName' => $zipName,
            'extractPath' => $extractPath,
            'mode' => $mode,
            'baseDir' => __DIR__
        ]);
        
        $fullExtractPath = __DIR__ . '/' . $extractPath;
        
        // Security check - ensure extract path is within the application directory
        if (!empty($extractPath)) {
            if (strpos($extractPath, '..') !== false || 
                strpos($extractPath, '//') !== false || 
                strpos($extractPath, '\\') !== false ||
                strpos($extractPath, ':') !== false) {
                SecurityHelper::jsonError('Invalid extract path - contains dangerous characters.');
            }
            
            // Enhanced validation: allow more characters for subdirectories
            if (!preg_match('/^[a-zA-Z0-9_\-\/]+$/', $extractPath)) {
                SecurityHelper::jsonError('Invalid extract path - use only letters, numbers, underscores, hyphens, and forward slashes.');
            }
        }
        
        // Handle different modes
        if ($mode === 'overwrite' && is_dir($fullExtractPath)) {
            // Remove existing directory and its contents
            if (!FileHelper::deleteFolder($fullExtractPath)) {
                SecurityHelper::jsonError('Failed to remove existing directory for overwrite.');
            }
        }
        
        // Create directory if it doesn't exist (skip for root directory)
        if (!empty($extractPath) && !is_dir($fullExtractPath)) {
            if (!mkdir($fullExtractPath, 0755, true)) {
                SecurityHelper::jsonError('Failed to create extract directory.');
            }
        }
        
        // For merge mode, ensure directory exists but don't delete anything
        if ($mode === 'merge' && !empty($extractPath) && !is_dir($fullExtractPath)) {
            if (!mkdir($fullExtractPath, 0755, true)) {
                SecurityHelper::jsonError('Failed to create extract directory for merge.');
            }
        }
        
        $zip = new ZipArchive();
        if ($zip->open($zipPath) !== TRUE) {
            SecurityHelper::jsonError('Failed to open ZIP file.');
        }
        
        if ($zip->extractTo($fullExtractPath)) {
            $zip->close();
            Logger::logAction('zip_extract', [
                'file' => $zipName, 
                'path' => $extractPath,
                'mode' => $mode
            ]);
            SecurityHelper::jsonResponse([
                'success' => true, 
                'message' => 'ZIP file extracted successfully.',
                'extract_path' => $extractPath,
                'mode' => $mode
            ]);
        } else {
            $zip->close();
            SecurityHelper::jsonError('Failed to extract ZIP file.');
        }
    }

    /**
     * Handles checking if extract path exists and has content
     */
    private function handleCheckExtractPath() {
        $extractPath = $_POST['extractPath'] ?? '';
        
        // Validate extract path - allow empty for root directory
        $extractPath = trim($extractPath, '/\\');
        // Empty path means extract to root directory
        
        $fullExtractPath = __DIR__ . '/' . $extractPath;
        
        // Security check - ensure extract path is within the application directory
        if (!empty($extractPath)) {
            if (strpos($extractPath, '..') !== false || 
                strpos($extractPath, '//') !== false || 
                strpos($extractPath, '\\') !== false ||
                strpos($extractPath, ':') !== false) {
                SecurityHelper::jsonError('Invalid extract path - contains dangerous characters.');
            }
        }
        
        // Check if directory exists
        $exists = is_dir($fullExtractPath);
        $hasContent = false;
        
        if ($exists) {
            // Check if directory has content (files or subdirectories)
            $contents = scandir($fullExtractPath);
            $hasContent = count($contents) > 2; // More than just . and ..
        }
        
        SecurityHelper::jsonResponse([
            'exists' => $exists,
            'hasContent' => $hasContent,
            'path' => $extractPath
        ]);
    }
    
    /**
     * Handles file search operations
     */
    private function handleSearchFiles() {
        $directory = $_GET['directory'] ?? $this->baseDir;
        $pattern = $_GET['pattern'] ?? '';
        $searchType = $_GET['type'] ?? 'name'; // name, content
        $recursive = isset($_GET['recursive']) && $_GET['recursive'] === '1';
        $extensions = isset($_GET['extensions']) ? explode(',', $_GET['extensions']) : [];
        
        try {
            // Handle Windows paths more gracefully
            $directory = str_replace('\\', '/', $directory);
            
            // If no directory specified, use current directory
            if (empty($directory)) {
                $directory = $this->baseDir;
            }
            
            // Get the real path to ensure it's valid
            $realDirectory = realpath($directory);
            if (!$realDirectory || !is_dir($realDirectory)) {
                HelperUtils::sendErrorResponse('Directory does not exist: ' . $directory);
            }
            
            // Use the real path for searching
            $directory = $realDirectory;
            
            $results = [];
            switch ($searchType) {
                case 'name':
                    if (empty($pattern)) {
                        // If no pattern, return all files in directory
                        $results = FileSearchManager::searchByName($directory, '.*', $recursive);
                    } else {
                        $results = FileSearchManager::searchByName($directory, $pattern, $recursive);
                    }
                    break;
                    
                case 'content':
                    if (empty($pattern)) {
                        HelperUtils::sendErrorResponse('Search text is required for content search');
                    }
                    $results = FileSearchManager::searchByContent($directory, $pattern, $extensions);
                    break;
                    
                default:
                    HelperUtils::sendErrorResponse('Invalid search type');
            }
            
            // Log the search for debugging
            Logger::logDebug("Search performed", [
                'search_type' => $searchType,
                'pattern' => $pattern,
                'directory' => $directory,
                'recursive' => $recursive,
                'results_count' => count($results)
            ]);
            
            HelperUtils::sendSuccessResponse([
                'results' => $results,
                'count' => count($results),
                'search_type' => $searchType,
                'pattern' => $pattern,
                'directory' => $directory
            ]);
            
        } catch (Exception $e) {
            HelperUtils::sendErrorResponse('Search failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Handles file filtering operations
     */
    private function handleFilterFiles() {
        $files = json_decode($_GET['files'] ?? '[]', true);
        $minSize = isset($_GET['min_size']) ? (int)$_GET['min_size'] : 0;
        $maxSize = isset($_GET['max_size']) ? (int)$_GET['max_size'] : null;
        $startDate = isset($_GET['start_date']) ? strtotime($_GET['start_date']) : null;
        $endDate = isset($_GET['end_date']) ? strtotime($_GET['end_date']) : null;
        
        try {
            if (!is_array($files)) {
                HelperUtils::sendErrorResponse('Invalid files data');
            }
            
            $filtered = $files;
            
            // Filter by size
            if ($minSize > 0 || $maxSize !== null) {
                $filtered = FileSearchManager::filterBySize($filtered, $minSize, $maxSize);
            }
            
            // Filter by date
            if ($startDate !== null || $endDate !== null) {
                $filtered = FileSearchManager::filterByDate($filtered, $startDate, $endDate);
            }
            
            HelperUtils::sendSuccessResponse([
                'original_count' => count($files),
                'filtered_count' => count($filtered),
                'results' => array_values($filtered)
            ]);
            
        } catch (Exception $e) {
            HelperUtils::sendErrorResponse('Filtering failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Handles setting file permissions
     */
        private function handleSetPermissions() {
        $path = $_POST['path'] ?? '';
        $permissions = isset($_POST['permissions']) ? octdec($_POST['permissions']) : 0644;
        $recursive = isset($_POST['recursive']) && $_POST['recursive'] === '1';
        
        try {
            if (empty($path)) {
                HelperUtils::sendErrorResponse('Path is required');
            }
            
            // Handle Windows paths more gracefully
            $path = str_replace('\\', '/', $path);
            
            // Validate the path exists
            if (!file_exists($path)) {
                HelperUtils::sendErrorResponse('Path does not exist: ' . $path);
            }
            
            $result = PermissionManager::setPermissions($path, $permissions, $recursive);
            
            if ($result['status'] === 'success') {
                HelperUtils::sendSuccessResponse($result);
            } else {
                HelperUtils::sendErrorResponse($result['message']);
            }
            
        } catch (Exception $e) {
            HelperUtils::sendErrorResponse('Permission setting failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Handles getting file permissions
     */
        private function handleGetPermissions() {
        $path = $_GET['path'] ?? '';
        
        try {
            if (empty($path)) {
                HelperUtils::sendErrorResponse('Path is required');
            }
            
            // Handle Windows paths more gracefully
            $path = str_replace('\\', '/', $path);
            
            // Validate the path exists
            if (!file_exists($path)) {
                HelperUtils::sendErrorResponse('Path does not exist: ' . $path);
            }
            
            $result = PermissionManager::getPermissions($path);
            
            if ($result['status'] === 'success') {
                HelperUtils::sendSuccessResponse($result);
            } else {
                HelperUtils::sendErrorResponse($result['message']);
            }
            
        } catch (Exception $e) {
            HelperUtils::sendErrorResponse('Permission retrieval failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Handles fixing WordPress permissions
     */
    private function handleFixWordPressPermissions() {
        try {
            $results = PermissionManager::fixWordPressPermissions($this->baseDir);
            
            HelperUtils::sendSuccessResponse([
                'message' => 'WordPress permissions fixed',
                'results' => $results
            ]);
            
        } catch (FileOperationException $e) {
            // Provide a more user-friendly error message
            $errorMessage = $e->getMessage();
            if (strpos($errorMessage, 'WordPress files/folders not found:') !== false) {
                HelperUtils::sendErrorResponse($errorMessage);
            } else {
                HelperUtils::sendErrorResponse('Some WordPress files/folders do not exist. ' . $errorMessage);
            }
        } catch (Exception $e) {
            HelperUtils::sendErrorResponse('WordPress permission fix failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Handles system health monitoring
     */
    private function handleSystemHealth() {
        try {
            $report = SystemHealthManager::generateHealthReport($this->baseDir);
            
            HelperUtils::sendSuccessResponse([
                'message' => 'System health report generated',
                'report' => $report
            ]);
            
        } catch (FileOperationException $e) {
            HelperUtils::sendErrorResponse($e->getMessage());
        } catch (Exception $e) {
            HelperUtils::sendErrorResponse('System health report failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Debug search functionality
     */
    private function handleDebugSearch() {
        try {
            $directory = $_GET['directory'] ?? $this->baseDir;
            $directory = str_replace('\\', '/', $directory);
            $realDirectory = realpath($directory);
            
            $debugInfo = [
                'original_directory' => $directory,
                'real_directory' => $realDirectory,
                'directory_exists' => is_dir($realDirectory),
                'base_dir' => $this->baseDir,
                'current_working_dir' => getcwd(),
                'files_in_directory' => []
            ];
            
            if ($realDirectory && is_dir($realDirectory)) {
                $files = scandir($realDirectory);
                foreach ($files as $file) {
                    if ($file !== '.' && $file !== '..') {
                        $fullPath = $realDirectory . '/' . $file;
                        $debugInfo['files_in_directory'][] = [
                            'name' => $file,
                            'path' => $fullPath,
                            'is_file' => is_file($fullPath),
                            'is_dir' => is_dir($fullPath),
                            'size' => is_file($fullPath) ? filesize($fullPath) : 0
                        ];
                    }
                }
            }
            
            HelperUtils::sendSuccessResponse($debugInfo);
            
        } catch (Exception $e) {
            HelperUtils::sendErrorResponse('Debug search failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Test search functionality
     */
    private function handleTestSearch() {
        try {
            $directory = $_GET['directory'] ?? $this->baseDir;
            $pattern = $_GET['pattern'] ?? '.*';
            
            // Test the search function directly
            $results = FileSearchManager::searchByName($directory, $pattern, true);
            
            // Also test with non-recursive search
            $resultsNonRecursive = FileSearchManager::searchByName($directory, $pattern, false);
            
            // Test with simple directory listing
            $simpleResults = [];
            if (is_dir($directory)) {
                $items = scandir($directory);
                foreach ($items as $item) {
                    if ($item !== '.' && $item !== '..') {
                        $fullPath = $directory . DIRECTORY_SEPARATOR . $item;
                        $isDir = is_dir($fullPath);
                        if (preg_match('/' . preg_quote($pattern, '/') . '/i', $item)) {
                            $simpleResults[] = [
                                'name' => $item,
                                'path' => str_replace($directory, '', $fullPath),
                                'size' => $isDir ? 0 : filesize($fullPath),
                                'modified' => filemtime($fullPath),
                                'permissions' => substr(sprintf('%o', fileperms($fullPath)), -4),
                                'type' => $isDir ? 'folder' : 'file'
                            ];
                        }
                    }
                }
            }
            
            $testInfo = [
                'directory' => $directory,
                'pattern' => $pattern,
                'total_results' => count($results),
                'folders' => array_filter($results, function($r) { return $r['type'] === 'folder'; }),
                'files' => array_filter($results, function($r) { return $r['type'] === 'file'; }),
                'all_results' => $results,
                'non_recursive_results' => $resultsNonRecursive,
                'non_recursive_folders' => array_filter($resultsNonRecursive, function($r) { return $r['type'] === 'folder'; }),
                'non_recursive_files' => array_filter($resultsNonRecursive, function($r) { return $r['type'] === 'file'; }),
                'simple_results' => $simpleResults,
                'simple_folders' => array_filter($simpleResults, function($r) { return $r['type'] === 'folder'; }),
                'simple_files' => array_filter($simpleResults, function($r) { return $r['type'] === 'file'; })
            ];
            
            HelperUtils::sendSuccessResponse($testInfo);
            
        } catch (Exception $e) {
            HelperUtils::sendErrorResponse('Test search failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Check if a specific folder exists
     */
    private function handleCheckFolder() {
        try {
            $folderName = $_GET['folder'] ?? 'wp-content';
            $directory = $_GET['directory'] ?? $this->baseDir;
            
            // Check if folder exists
            $folderPath = $directory . DIRECTORY_SEPARATOR . $folderName;
            $exists = is_dir($folderPath);
            
            // List all directories in the base directory
            $allDirs = [];
            if (is_dir($directory)) {
                $items = scandir($directory);
                foreach ($items as $item) {
                    if ($item !== '.' && $item !== '..' && is_dir($directory . DIRECTORY_SEPARATOR . $item)) {
                        $allDirs[] = $item;
                    }
                }
            }
            
            $result = [
                'folder_name' => $folderName,
                'folder_path' => $folderPath,
                'exists' => $exists,
                'all_directories' => $allDirs,
                'base_directory' => $directory
            ];
            
            HelperUtils::sendSuccessResponse($result);
            
        } catch (Exception $e) {
            HelperUtils::sendErrorResponse('Check folder failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Update WordPress salts in wp-config.php
     */
    private function handleUpdateWordPressSalts() {
        try {
            // Find wp-config.php file
            $wpConfigPath = $this->findWordPressConfig();
            if (!$wpConfigPath) {
                HelperUtils::sendErrorResponse('WordPress configuration file (wp-config.php) not found in the root directory');
                return;
            }
            
            // Check if wp-config.php is readable and writable
            if (!is_readable($wpConfigPath)) {
                HelperUtils::sendErrorResponse('wp-config.php is not readable');
                return;
            }
            
            if (!is_writable($wpConfigPath)) {
                HelperUtils::sendErrorResponse('wp-config.php is not writable. Please check file permissions.');
                return;
            }
            
            // Fetch new salts from WordPress.org API
            $salts = $this->fetchWordPressSalts();
            if (!$salts) {
                HelperUtils::sendErrorResponse('Failed to fetch new salts from WordPress.org API');
                return;
            }
            
            // Backup the original wp-config.php
            $backupPath = $wpConfigPath . '.backup.' . date('Y-m-d-H-i-s');
            if (!copy($wpConfigPath, $backupPath)) {
                HelperUtils::sendErrorResponse('Failed to create backup of wp-config.php');
                return;
            }
            
            // Read the current wp-config.php
            $configContent = file_get_contents($wpConfigPath);
            if ($configContent === false) {
                HelperUtils::sendErrorResponse('Failed to read wp-config.php');
                return;
            }
            
            // Replace the salts section
            $updatedContent = $this->replaceWordPressSalts($configContent, $salts);
            if ($updatedContent === false) {
                HelperUtils::sendErrorResponse('Failed to update salts in wp-config.php');
                return;
            }
            
            // Write the updated content back to wp-config.php
            if (file_put_contents($wpConfigPath, $updatedContent) === false) {
                HelperUtils::sendErrorResponse('Failed to write updated wp-config.php');
                return;
            }
            
            // Check if wp-salt.php was created
            $saltFilePath = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'wp-salt.php';
            $saltFileCreated = file_exists($saltFilePath);
            
            // Log the action
            Logger::logSecurity('WordPress salts updated', [
                'wp_config_path' => $wpConfigPath,
                'backup_path' => $backupPath,
                'salts_updated' => array_keys($salts),
                'salt_file_created' => $saltFileCreated
            ]);
            
            $response = [
                'message' => 'WordPress salts updated successfully',
                'backup_path' => $backupPath,
                'salts_updated' => array_keys($salts)
            ];
            
            if ($saltFileCreated) {
                $response['salt_file_created'] = true;
                $response['salt_file_path'] = $saltFilePath;
            }
            
            HelperUtils::sendSuccessResponse($response);
            
        } catch (Exception $e) {
            HelperUtils::sendErrorResponse('Failed to update WordPress salts: ' . $e->getMessage());
        }
    }
    
    /**
     * Find WordPress configuration file
     */
    private function findWordPressConfig() {
        // Look for wp-config.php in the same directory as delete.php
        $wpConfigPath = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'wp-config.php';
        
        if (file_exists($wpConfigPath)) {
            return $wpConfigPath;
        }
        
        return null;
    }
    
    /**
     * Fetch new salts from WordPress.org API
     */
    private function fetchWordPressSalts() {
        $apiUrl = 'https://api.wordpress.org/secret-key/1.1/salt/';
        
        $context = stream_context_create([
            'http' => [
                'timeout' => 30,
                'user_agent' => 'WordPress Tools Kit/1.0'
            ]
        ]);
        
        $response = file_get_contents($apiUrl, false, $context);
        if ($response === false) {
            return null;
        }
        
        // Parse the response to extract salt definitions
        $salts = [];
        $lines = explode("\n", $response);
        
        foreach ($lines as $line) {
            $line = trim($line);
            if (preg_match("/define\s*\(\s*'([^']+)',\s*'([^']+)'\s*\);/", $line, $matches)) {
                $salts[$matches[1]] = $matches[2];
            }
        }
        
        return $salts;
    }
    
    /**
     * Replace WordPress salts in configuration content
     */
    private function replaceWordPressSalts($content, $newSalts) {
        $newContent = $content;
        $replaced = false;
        
        // Case 1: Find and replace require('wp-salt.php') with actual salt definitions
        $requirePattern = "/require\s*\(\s*['\"]wp-salt\.php['\"]\s*\);/";
        if (preg_match($requirePattern, $newContent)) {
            // Build the salt definitions to replace the require statement
            $saltDefinitions = '';
            foreach ($newSalts as $key => $value) {
                $saltDefinitions .= "define( '$key', '$value' );\n";
            }
            
            // Replace the require statement with actual salt definitions
            $newContent = preg_replace($requirePattern, $saltDefinitions, $newContent);
            $replaced = true;
        }
        
        // Case 2: Find and replace individual define statements for each salt
        foreach ($newSalts as $key => $value) {
            // Pattern to match any define statement for this salt key
            $saltPattern = '/define\s*\(\s*[\'"]' . preg_quote($key, '/') . '[\'"],\s*[\'"][^\'"]*[\'"]\s*\);/';
            if (preg_match($saltPattern, $newContent)) {
                $newContent = preg_replace($saltPattern, "define( '$key', '$value' );", $newContent);
                $replaced = true;
            }
        }
        
        return $replaced ? $newContent : false;
    }

    // ─────────────────────────────────────────────────────────────
    //  MALWARE SCANNER HANDLERS
    // ─────────────────────────────────────────────────────────────

    /** Start a new scan session and return the session ID + total file count. */
    private function handleStartScan() {
        // Accept custom root directory and exclude paths from POST
        $customRoot = trim($_POST['scanRootDir'] ?? '');
        $excludeRaw = trim($_POST['scanExcludePaths'] ?? '');

        // Determine scan directory
        if ($customRoot && is_dir($customRoot)) {
            $dir = realpath($customRoot);
        } else {
            $dir = realpath($this->baseDir);
        }

        // Parse exclude paths
        $excludeDirs = [];
        if ($excludeRaw) {
            $excludeDirs = array_filter(array_map('trim', explode("\n", $excludeRaw)));
        }

        // Get files to scan with custom exclusions
        $files = MalwareScanner::getFilesToScan($dir, $excludeDirs);

        $session = SessionManager::startSession('scan', [
            'directory' => $dir,
            'files'     => $files,
            'scanned'   => [],
            'infected'  => [],
        ]);
        SecurityHelper::jsonResponse(['sessionId' => $session, 'total' => count($files)]);
        exit;
    }

    /** Process one batch of files; called repeatedly until finished = true. */
    private function handleProcessScan() {
        $sessionId = $_POST['sessionId'] ?? '';

        $lock = SessionManager::acquireLock('scan', $sessionId);
        if ($lock === false) {
            SecurityHelper::jsonResponse(['busy' => true, 'retry' => true]);
            exit;
        }

        try {
            $data = SessionManager::loadSession('scan', $sessionId);
            if (!$data) SecurityHelper::jsonError('Scan session not found', 404);

            $files    = $data['files'];
            $scanned  = $data['scanned'];
            $infected = $data['infected'];
            $baseDir  = $data['directory'];

            $batchResult = [];

            // Time-budgeted loop: scan files until the request's time slice is
            // spent, then let the browser request the next batch. Scanning big
            // files is slower, so adaptive sizing keeps each round-trip bounded.
            $budget = new JobBudget();
            $processed = 0;
            while (!empty($files) && $budget->hasTime()) {
                $path = array_shift($files);
                $hits = MalwareScanner::scanFile($path);
                $scanned[] = $path;
                if (!empty($hits)) {
                    $rel = ltrim(str_replace($baseDir, '', $path), '/\\');
                    $infected[$path] = ['path' => $path, 'relative_path' => $rel, 'matches' => $hits];
                    $batchResult[$path] = ['relative_path' => $rel, 'matches' => $hits];
                }
                $processed++;
            }

            $data['files']    = $files;
            $data['scanned']  = $scanned;
            $data['infected'] = $infected;
            $finished         = empty($files);

            SessionManager::saveSession('scan', $sessionId, $data);

            $total = count($scanned) + count($files);
            SecurityHelper::jsonResponse([
                'progress'       => $total > 0 ? count($scanned) / $total : 1,
                'scanned_count'  => count($scanned),
                'infected_count' => count($infected),
                'finished'       => $finished,
                'sessionId'      => $sessionId,
                'batch_results'  => $batchResult,
                'processed'      => $processed,
                'batchSize'      => $budget->nextBatchSize($processed),
            ]);
        } finally {
            SessionManager::releaseLock($lock);
        }
        exit;
    }

    /**
     * Quarantine or permanently delete a list of infected files.
     * POST: files[] (absolute paths), action (quarantine|delete), sessionId
     */
    private function handleActOnMalware() {
        $filePaths = $_POST['files']     ?? [];
        $action    = $_POST['action']    ?? 'quarantine';
        $sessionId = $_POST['sessionId'] ?? '';

        if (empty($filePaths)) SecurityHelper::jsonError('No files specified');
        if (!in_array($action, ['quarantine', 'delete'])) SecurityHelper::jsonError('Invalid action');

        $quarantineDir = __DIR__ . '/quarantine';
        if ($action === 'quarantine' && !is_dir($quarantineDir)) {
            if (!mkdir($quarantineDir, 0755, true))
                SecurityHelper::jsonError('Could not create quarantine directory — check permissions');
        }

        $baseDir  = $this->baseDir;
        $selfPath = realpath(__FILE__);
        $results  = [];

        foreach ($filePaths as $fp) {
            $real = realpath($fp);

            if (!$real || !file_exists($real)) {
                $results[$fp] = ['status' => 'not_found', 'message' => 'File not found'];
                continue;
            }
            if (strpos($real, $baseDir) !== 0) {
                $results[$fp] = ['status' => 'error', 'message' => 'Path outside base directory'];
                continue;
            }
            if ($real === $selfPath) {
                $results[$fp] = ['status' => 'skipped', 'message' => 'Cannot act on this script'];
                continue;
            }

            if ($action === 'quarantine') {
                $rel      = ltrim(str_replace($baseDir, '', $real), '/\\');
                $safeName = preg_replace('/[\/\\\\:]+/', '_', $rel) . '_' . date('YmdHis');
                $dest     = $quarantineDir . '/' . $safeName;

                if (rename($real, $dest)) {
                    $results[$fp] = ['status' => 'quarantined', 'dest' => $dest];
                    Logger::logAction('File quarantined', ['from' => $real, 'to' => $dest]);
                } else {
                    $results[$fp] = ['status' => 'error', 'message' => 'rename() failed — check permissions'];
                }
            } else { // delete
                if (@unlink($real)) {
                    $results[$fp] = ['status' => 'deleted'];
                    Logger::logAction('Infected file deleted', ['path' => $real]);
                } else {
                    $results[$fp] = ['status' => 'error', 'message' => 'unlink() failed — check permissions'];
                }
            }
        }

        if ($sessionId) SessionManager::deleteSession('scan', $sessionId);

        SecurityHelper::jsonResponse(['results' => $results]);
        exit;
    }

    /** List all files currently in the quarantine folder. */
    private function handleListQuarantine() {
        $dir   = __DIR__ . '/quarantine';
        $items = [];
        if (is_dir($dir)) {
            foreach (glob($dir . '/*') as $f) {
                $items[] = [
                    'name'     => basename($f),
                    'size'     => is_file($f) ? filesize($f) : 0,
                    'modified' => filemtime($f),
                    'type'     => is_dir($f) ? 'folder' : 'file',
                ];
            }
        }
        SecurityHelper::jsonResponse(['items' => $items, 'count' => count($items)]);
        exit;
    }

    /** Move a quarantined file back to its original location. */
    private function handleRestoreQuarantine() {
        $name          = basename($_POST['name'] ?? '');
        $quarantineDir = realpath(__DIR__ . '/quarantine');

        if (!$quarantineDir || !$name) SecurityHelper::jsonError('Invalid request');

        $srcPath = $quarantineDir . '/' . $name;
        if (!file_exists($srcPath) || strpos(realpath($srcPath), $quarantineDir) !== 0)
            SecurityHelper::jsonError('File not found in quarantine');

        // Reconstruct original relative path: strip trailing _YYYYMMDDHHiiss timestamp
        $withoutTs   = preg_replace('/_\d{14}$/', '', $name);
        $relRestored = str_replace('_', '/', $withoutTs);
        $destPath    = $this->baseDir . '/' . ltrim($relRestored, '/');

        if (!is_dir(dirname($destPath))) mkdir(dirname($destPath), 0755, true);

        if (rename($srcPath, $destPath)) {
            Logger::logAction('Quarantined file restored', ['from' => $srcPath, 'to' => $destPath]);
            SecurityHelper::jsonResponse(['success' => true, 'restored_to' => $destPath]);
        } else {
            SecurityHelper::jsonError('rename() failed — check permissions');
        }
        exit;
    }

    /** Permanently delete every file in the quarantine folder. */
    private function handleEmptyQuarantine() {
        $dir     = __DIR__ . '/quarantine';
        $deleted = 0;
        if (is_dir($dir)) {
            foreach (glob($dir . '/*') as $f) {
                if (is_file($f) && @unlink($f)) $deleted++;
            }
        }
        Logger::logAction('Quarantine emptied', ['deleted' => $deleted]);
        SecurityHelper::jsonResponse(['success' => true, 'deleted' => $deleted]);
        exit;
    }

    // ─────────────────────────────────────────────────────────────
    //  DATABASE CLEANER HANDLERS
    // ─────────────────────────────────────────────────────────────

    /** Scan the database and return counts of cleanable items. */
    private function handleDbScan() {
        try {
            $cleaner = new DatabaseCleaner();
            $counts = $cleaner->scan();
            $cleaner->close();
            SecurityHelper::jsonResponse(['counts' => $counts]);
        } catch (Exception $e) {
            SecurityHelper::jsonError('Database scan failed: ' . $e->getMessage());
        }
    }

    /** Get paginated list of items to clean for a category. */
    private function handleDbGetList() {
        try {
            $category = $_GET['category'] ?? '';
            $page = max(1, (int)($_GET['page'] ?? 1));
            if (!in_array($category, ['transients','site_transients','revisions','spam_comments','trashed_comments','orphaned_postmeta','orphaned_commentmeta','autoload_options','trashed_posts','malware_posts','malware_comments','malware_options'])) {
                SecurityHelper::jsonError('Invalid category');
            }
            $cleaner = new DatabaseCleaner();
            $result = $cleaner->getList($category, $page);
            $cleaner->close();
            SecurityHelper::jsonResponse($result);
        } catch (Exception $e) {
            SecurityHelper::jsonError('Failed to get list: ' . $e->getMessage());
        }
    }

    /** Clean selected items in a category. */
    private function handleDbCleanItems() {
        try {
            $category = $_POST['category'] ?? '';
            $ids = $_POST['ids'] ?? [];
            if (!in_array($category, ['transients','site_transients','revisions','spam_comments','trashed_comments','autoload_options','trashed_posts','malware_posts','malware_comments','malware_options'])) {
                SecurityHelper::jsonError('Invalid category');
            }
            if (empty($ids)) {
                SecurityHelper::jsonError('No items selected');
            }
            $cleaner = new DatabaseCleaner();
            $result = $cleaner->clean($category, $ids);
            $cleaner->close();
            Logger::logAction('Database cleaned (selected)', ['category' => $category, 'deleted' => $result['deleted'] ?? 0]);
            SecurityHelper::jsonResponse($result);
        } catch (Exception $e) {
            SecurityHelper::jsonError('Clean failed: ' . $e->getMessage());
        }
    }

    /** Clean all items in a category at once. */
    private function handleDbCleanAll() {
        try {
            $category = $_POST['category'] ?? '';
            if (!in_array($category, ['transients','site_transients','revisions','spam_comments','trashed_comments','orphaned_postmeta','orphaned_commentmeta','autoload_options','trashed_posts','malware_posts','malware_comments','malware_options'])) {
                SecurityHelper::jsonError('Invalid category');
            }
            $cleaner = new DatabaseCleaner();
            $result = $cleaner->cleanAll($category);
            $cleaner->close();
            Logger::logAction('Database cleaned (all)', ['category' => $category, 'deleted' => $result['deleted'] ?? 0]);
            SecurityHelper::jsonResponse($result);
        } catch (Exception $e) {
            SecurityHelper::jsonError('Clean all failed: ' . $e->getMessage());
        }
    }

    /** Execute a safe diagnostic command. */
    private function handleExecCmd() {
        $cmd = $_POST['cmd'] ?? '';
        if (empty($cmd)) SecurityHelper::jsonError('No command provided');

        // Whitelist of allowed command prefixes — only read-only, non-destructive commands
        $allowedPrefixes = [
            'find ', 'ls ', 'df ', 'php -v', 'php -m', 'whoami', 'uptime',
            'cat ', 'head ', 'tail ', 'grep ', 'wc ', 'pwd', 'uname ',
            'du ', 'stat ', 'file ', 'echo ', 'env ', 'printenv ',
            'ps ', 'netstat ', 'ss ', 'ip ', 'hostname ',
        ];
        $cmdLower = strtolower($cmd);
        $blocked = [
            'rm ', 'unlink ', 'chmod ', 'chown ', 'mkfs ', 'dd ', 'shutdown',
            'reboot ', 'kill ', 'wget ', 'curl ', 'scp ', 'ssh ', 'sudo',
            'apt ', 'yum ', 'pip ', 'npm ', 'git ', 'mv ', 'touch ',
            '> ', '>> ', '| xargs kill', '| xargs rm', '| xargs chmod',
            ';', '`', '$(', '&&',
        ];
        $cmdTrimmed = trim($cmd);
        $isAllowed = false;
        foreach ($allowedPrefixes as $prefix) {
            if (strpos($cmdTrimmed, $prefix) === 0) {
                $isAllowed = true;
                break;
            }
        }
        if (!$isAllowed) {
            SecurityHelper::jsonError('Command not allowed. Only diagnostic/read-only commands permitted.');
        }
        foreach ($blocked as $b) {
            if (stripos($cmdTrimmed, $b) !== false) {
                SecurityHelper::jsonError('Blocked command pattern detected: ' . htmlspecialchars($b));
            }
        }

        // Only allow safe redirects, cap output
        $safeCmd = escapeshellcmd($cmdTrimmed) . ' 2>&1 | head -500';
        $output = '';
        $exitCode = 0;
        // Env::isFunctionAvailable() respects php.ini disable_functions, unlike
        // function_exists(), so on locked-down cPanel hosts we degrade cleanly
        // with guidance instead of emitting warnings / returning null silently.
        if (Env::isFunctionAvailable('shell_exec')) {
            $output = shell_exec($safeCmd);
        } elseif (Env::isFunctionAvailable('exec')) {
            exec($safeCmd, $outputLines, $exitCode);
            $output = implode("\n", $outputLines);
        } elseif (Env::isFunctionAvailable('system')) {
            ob_start();
            system($safeCmd, $exitCode);
            $output = ob_get_clean();
        } else {
            // Provide guidance on how to enable command execution
            $phpIni = ini_get('disable_functions');
            SecurityHelper::jsonError(
                'Command execution is blocked. The following functions are disabled in php.ini: ' .
                ($phpIni ?: 'shell_exec, exec, system') .
                "\n\n" .
                'To enable, edit your php.ini file and remove these functions from disable_functions:\n' .
                '  disable_functions = ...\n\n' .
                'Change to:\n' .
                '  disable_functions =\n\n' .
                'OR remove shell_exec, exec, system from the list.\n\n' .
                'Then restart PHP-FPM/Apache: systemctl restart php-fpm OR systemctl restart apache2\n\n' .
                'If you cannot edit php.ini, contact your hosting provider.'
            );
        }

        if ($output === null || $output === '') {
            SecurityHelper::jsonResponse(['output' => '(no output — command may be blocked by server config)', 'empty' => true]);
        } else {
            SecurityHelper::jsonResponse(['output' => htmlspecialchars(trim($output)), 'empty' => false]);
        }
        exit;
    }

    /* ═══════════════ SEARCH-REPLACE HANDLERS ═══════════════ */

    private function handleSrTables() {
        try {
            $kit = new WpToolkit($this->baseDir);
            $tables = $kit->listTables();
            $kit->close();
            SecurityHelper::jsonResponse(['tables' => $tables]);
        } catch (Exception $e) {
            SecurityHelper::jsonError('Failed to list tables: ' . $e->getMessage());
        }
    }

    private function handleSrStart() {
        try {
            $search = $_POST['search'] ?? '';
            $replace = $_POST['replace'] ?? '';
            $dryRun = !empty($_POST['dryrun']);
            $tables = $_POST['tables'] ?? [];
            if ($search === '') SecurityHelper::jsonError('Search text is required');
            if (!is_array($tables) || empty($tables)) {
                // Default: all tables in the database.
                $kit = new WpToolkit($this->baseDir);
                $tables = $kit->listTables();
                $kit->close();
            }
            $sessionId = SessionManager::startSession('search_replace', [
                'search' => $search,
                'replace' => $replace,
                'dryrun' => $dryRun ? 1 : 0,
                'tables' => array_values($tables),
                'done' => [],
                'rows' => 0,
                'cells' => 0,
            ]);
            SecurityHelper::jsonResponse(['sessionId' => $sessionId, 'total' => count($tables)]);
        } catch (Exception $e) {
            SecurityHelper::jsonError('Failed to start: ' . $e->getMessage());
        }
    }

    private function handleSrProcess() {
        $sessionId = $_POST['sessionId'] ?? '';
        $lock = SessionManager::acquireLock('search_replace', $sessionId);
        if ($lock === false) { SecurityHelper::jsonResponse(['busy' => true, 'retry' => true]); exit; }
        try {
            $data = SessionManager::loadSession('search_replace', $sessionId);
            if (!$data) SecurityHelper::jsonError(['error' => 'Session not found']);

            $tables = $data['tables'];
            $done = $data['done'];
            $results = [];
            $kit = new WpToolkit($this->baseDir);
            $budget = new JobBudget(1, 50);
            $processed = 0;
            // Process one table per iteration (a table can be large), bounded by time.
            while (!empty($tables) && $budget->hasTime()) {
                $table = array_shift($tables);
                $r = $kit->searchReplaceTable($table, $data['search'], $data['replace'], (bool)$data['dryrun']);
                $data['rows'] += $r['rows_changed'];
                $data['cells'] += $r['cells_changed'];
                $results[$table] = $r;
                $done[] = $table;
                $processed++;
            }
            $kit->close();

            $data['tables'] = $tables;
            $data['done'] = $done;
            SessionManager::saveSession('search_replace', $sessionId, $data);
            $total = count($done) + count($tables);
            $finished = count($tables) === 0;
            $response = [
                'progress' => $total > 0 ? count($done) / $total : 1,
                'results' => $results,
                'finished' => $finished,
                'rows_changed' => $data['rows'],
                'cells_changed' => $data['cells'],
                'dryrun' => (int)$data['dryrun'],
            ];
            if ($finished) SessionManager::deleteSession('search_replace', $sessionId);
            SecurityHelper::jsonResponse($response);
        } catch (Exception $e) {
            SecurityHelper::jsonError('Process failed: ' . $e->getMessage());
        } finally {
            SessionManager::releaseLock($lock);
        }
        exit;
    }

    /* ═══════════════ ADMIN USER HANDLERS ═══════════════ */

    private function handleWpListAdmins() {
        try {
            $kit = new WpToolkit($this->baseDir);
            $admins = $kit->listAdmins();
            $kit->close();
            SecurityHelper::jsonResponse(['admins' => $admins]);
        } catch (Exception $e) {
            SecurityHelper::jsonError('Failed to list admins: ' . $e->getMessage());
        }
    }

    private function handleWpResetPassword() {
        try {
            $userId = (int)($_POST['user_id'] ?? 0);
            $password = $_POST['password'] ?? '';
            if ($userId <= 0) SecurityHelper::jsonError('Invalid user ID');
            if (strlen($password) < 6) SecurityHelper::jsonError('Password must be at least 6 characters');
            $kit = new WpToolkit($this->baseDir);
            $kit->resetPassword($userId, $password);
            $kit->close();
            Logger::logAction('WP password reset', ['user_id' => $userId]);
            SecurityHelper::jsonResponse(['success' => true, 'message' => 'Password updated successfully']);
        } catch (Exception $e) {
            SecurityHelper::jsonError('Reset failed: ' . $e->getMessage());
        }
    }

    private function handleWpCreateAdmin() {
        try {
            $login = trim($_POST['login'] ?? '');
            $email = trim($_POST['email'] ?? '');
            $password = $_POST['password'] ?? '';
            if ($login === '' || !preg_match('/^[a-zA-Z0-9_.\-@ ]{1,60}$/', $login)) {
                SecurityHelper::jsonError('Invalid username');
            }
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) SecurityHelper::jsonError('Invalid email');
            if (strlen($password) < 6) SecurityHelper::jsonError('Password must be at least 6 characters');
            $kit = new WpToolkit($this->baseDir);
            $newId = $kit->createAdmin($login, $email, $password);
            $kit->close();
            Logger::logAction('WP admin created', ['user_id' => $newId, 'login' => $login]);
            SecurityHelper::jsonResponse(['success' => true, 'user_id' => $newId,
                'message' => "Administrator '{$login}' created (ID {$newId})"]);
        } catch (Exception $e) {
            SecurityHelper::jsonError('Create failed: ' . $e->getMessage());
        }
    }

    /* ═══════════════ DATABASE EXPORT HANDLERS ═══════════════ */

    private function handleDbExportStart() {
        try {
            $kit = new WpToolkit($this->baseDir);
            $tables = $kit->listTables();
            $exportsDir = __DIR__ . '/db_exports';
            if (!is_dir($exportsDir)) mkdir($exportsDir, 0755, true);
            $fileName = 'db-export-' . date('Ymd-His') . '-' . bin2hex(random_bytes(4)) . '.sql';
            $filePath = $exportsDir . '/' . $fileName;
            $kit->writeExportHeader($filePath);
            $kit->close();

            $sessionId = SessionManager::startSession('db_export', [
                'tables' => $tables,
                'done' => [],
                'file' => $fileName,
                'rows' => 0,
            ]);
            SecurityHelper::jsonResponse(['sessionId' => $sessionId, 'total' => count($tables), 'file' => $fileName]);
        } catch (Exception $e) {
            SecurityHelper::jsonError('Export start failed: ' . $e->getMessage());
        }
    }

    private function handleDbExportProcess() {
        $sessionId = $_POST['sessionId'] ?? '';
        $lock = SessionManager::acquireLock('db_export', $sessionId);
        if ($lock === false) { SecurityHelper::jsonResponse(['busy' => true, 'retry' => true]); exit; }
        try {
            $data = SessionManager::loadSession('db_export', $sessionId);
            if (!$data) SecurityHelper::jsonError(['error' => 'Session not found']);

            $exportsDir = __DIR__ . '/db_exports';
            $filePath = $exportsDir . '/' . basename($data['file']);
            $tables = $data['tables'];
            $done = $data['done'];
            $kit = new WpToolkit($this->baseDir);
            $budget = new JobBudget(1, 50);
            $processed = 0;
            while (!empty($tables) && $budget->hasTime()) {
                $table = array_shift($tables);
                $data['rows'] += $kit->dumpTableToFile($table, $filePath);
                $done[] = $table;
                $processed++;
            }

            $finished = count($tables) === 0;
            if ($finished) $kit->writeExportFooter($filePath);
            $kit->close();

            $data['tables'] = $tables;
            $data['done'] = $done;
            SessionManager::saveSession('db_export', $sessionId, $data);
            $total = count($done) + count($tables);
            $response = [
                'progress' => $total > 0 ? count($done) / $total : 1,
                'finished' => $finished,
                'rows' => $data['rows'],
                'tables_done' => count($done),
                'file' => $data['file'],
                'size' => file_exists($filePath) ? filesize($filePath) : 0,
            ];
            if ($finished) SessionManager::deleteSession('db_export', $sessionId);
            SecurityHelper::jsonResponse($response);
        } catch (Exception $e) {
            SecurityHelper::jsonError('Export failed: ' . $e->getMessage());
        } finally {
            SessionManager::releaseLock($lock);
        }
        exit;
    }

    private function handleDbExportDownload() {
        $file = basename($_GET['file'] ?? '');
        $path = __DIR__ . '/db_exports/' . $file;
        if ($file === '' || !preg_match('/^db-export-[\w\-]+\.sql$/', $file) || !file_exists($path)) {
            SecurityHelper::jsonError('Export file not found', 404);
        }
        header('Content-Type: application/sql');
        header('Content-Disposition: attachment; filename="' . $file . '"');
        header('Content-Length: ' . filesize($path));
        readfile($path);
        exit;
    }

    /* ═══════════════ CORE INTEGRITY HANDLERS ═══════════════ */

    private function handleIntegrityStart() {
        try {
            $kit = new WpToolkit($this->baseDir);
            $wpRoot = $kit->baseDir();
            $version = $kit->getWpVersion();
            $kit->close();
            if (!$version) SecurityHelper::jsonError('Could not determine WordPress version');

            $locale = $_POST['locale'] ?? 'en_US';
            $url = 'https://api.wordpress.org/core/checksums/1.0/?version='
                . urlencode($version) . '&locale=' . urlencode($locale);
            $json = $this->httpGet($url);
            $parsed = $json ? json_decode($json, true) : null;
            if (!$parsed || empty($parsed['checksums'])) {
                SecurityHelper::jsonError('Could not fetch checksums from WordPress.org for version ' . $version);
            }
            $checksums = $parsed['checksums'];
            // Only verify core files (wp-admin, wp-includes, root) — skip wp-content.
            $files = array_keys($checksums);
            $sessionId = SessionManager::startSession('integrity', [
                'wp_root' => $wpRoot,
                'version' => $version,
                'checksums' => $checksums,
                'files' => $files,
                'done' => [],
                'modified' => [],
                'missing' => [],
            ]);
            SecurityHelper::jsonResponse(['sessionId' => $sessionId, 'total' => count($files), 'version' => $version]);
        } catch (Exception $e) {
            SecurityHelper::jsonError('Integrity start failed: ' . $e->getMessage());
        }
    }

    private function handleIntegrityProcess() {
        $sessionId = $_POST['sessionId'] ?? '';
        $lock = SessionManager::acquireLock('integrity', $sessionId);
        if ($lock === false) { SecurityHelper::jsonResponse(['busy' => true, 'retry' => true]); exit; }
        try {
            $data = SessionManager::loadSession('integrity', $sessionId);
            if (!$data) SecurityHelper::jsonError(['error' => 'Session not found']);

            $wpRoot = $data['wp_root'];
            $checksums = $data['checksums'];
            $files = $data['files'];
            $done = $data['done'];
            $modified = $data['modified'];
            $missing = $data['missing'];

            $budget = new JobBudget(5, 500);
            while (!empty($files) && $budget->hasTime()) {
                $rel = array_shift($files);
                $full = $wpRoot . '/' . $rel;
                $expected = $checksums[$rel] ?? null;
                if (!file_exists($full)) {
                    $missing[] = $rel;
                } elseif ($expected !== null && md5_file($full) !== $expected) {
                    $modified[] = $rel;
                }
                $done[] = $rel;
            }

            $data['files'] = $files;
            $data['done'] = $done;
            $data['modified'] = $modified;
            $data['missing'] = $missing;
            SessionManager::saveSession('integrity', $sessionId, $data);
            $total = count($done) + count($files);
            $finished = count($files) === 0;
            $response = [
                'progress' => $total > 0 ? count($done) / $total : 1,
                'finished' => $finished,
                'checked' => count($done),
                'modified' => $modified,
                'missing' => $missing,
                'modified_count' => count($modified),
                'missing_count' => count($missing),
            ];
            if ($finished) SessionManager::deleteSession('integrity', $sessionId);
            SecurityHelper::jsonResponse($response);
        } catch (Exception $e) {
            SecurityHelper::jsonError('Integrity check failed: ' . $e->getMessage());
        } finally {
            SessionManager::releaseLock($lock);
        }
        exit;
    }

    /** Simple HTTP GET helper (cURL, with file_get_contents fallback). */
    private function httpGet($url) {
        if (Env::isFunctionAvailable('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 20,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_USERAGENT => 'WordPress-Tools-Kit',
            ]);
            $out = curl_exec($ch);
            curl_close($ch);
            if ($out !== false) return $out;
        }
        if (ini_get('allow_url_fopen')) {
            $ctx = stream_context_create(['http' => ['timeout' => 20, 'user_agent' => 'WordPress-Tools-Kit']]);
            $out = @file_get_contents($url, false, $ctx);
            if ($out !== false) return $out;
        }
        return null;
    }

    /** Detect WordPress root directory. */
    private function handleDetectWpRoot() {
        // Look for wp-config.php to determine WordPress root
        $candidates = [
            $this->baseDir,
            dirname($this->baseDir),
        ];
        foreach ($candidates as $c) {
            if (is_dir($c) && file_exists($c . '/wp-config.php')) {
                SecurityHelper::jsonResponse(['root' => realpath($c)]);
                exit;
            }
        }
        SecurityHelper::jsonResponse(['root' => '']);
        exit;
    }
}

// --- SECURITY: AUTHENTICATION & IP RESTRICTION ---
SecurityHelper::ensureSession();

// --- CONFIGURATION ---
define('USERNAME', 'admin');
define('PASSWORD_HASH', password_hash('password', PASSWORD_DEFAULT));
$allowed_ips = [
    '127.0.0.1', // localhost
    '::1',       // IPv6 localhost
    // Add your allowed IPs here, e.g. '203.0.113.5',
];

// --- LOGIN LOGIC ---
if (isset($_POST['username']) && isset($_POST['password'])) {
    if ($_POST['username'] === USERNAME && password_verify($_POST['password'], PASSWORD_HASH)) {
        $_SESSION['loggedin'] = true;
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $login_error = 'Invalid credentials';
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// --- PAGE ACCESS CONTROL ---
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    // Display login form
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>WordPress Tools Kit</title>
        <style>
            body {
                font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #03A9F4 0%, #4CAF50 100%);
                color: #222;
                min-height: 100vh;
                margin: 0;
                padding: 0;
            }
            h1 {
                text-align: center;
                font-size: 2.2rem;
                font-weight: 700;
                letter-spacing: -1px;
                margin-bottom: 2rem;
                color: #0073e6;
            }
            .form-container {
                background: #fff;
                padding: 2.5rem 2rem 2rem 2rem;
                border-radius: 16px;
                box-shadow: 0 4px 24px 0 rgba(0,0,0,0.09);
                margin: 2.5rem auto 2rem auto;
                max-width: 700px;
            }
            .input-field {
                display: flex;
                align-items: center;
                margin-bottom: 14px;
                gap: 10px;
            }
            .input-field input {
                flex: 1;
                padding: 12px 14px;
                border: 1.5px solid #d0d7de;
                border-radius: 6px;
                font-size: 1.08rem;
                background: #f7fafc;
                transition: border 0.2s;
            }
            .input-field input:focus {
                border-color: #0073e6;
                outline: none;
                background: #fff;
            }
            button[type="submit"] {
                background-color: #28a745;
                color: white;
                padding: 12px 28px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-size: 1.15rem;
                margin-top: 18px;
                box-shadow: 0 2px 8px 0 rgba(40,167,69,0.07);
                transition: background 0.2s;
            }
            button[type="submit"]:hover {
                background-color: #218838;
            }
            p.error-text {
                color: red;
            }
    </style>
    </head>
    <body>
        <div class="form-container login-container">
            <h1>WordPress Tools Kit</h1>
            <?php if (isset($login_error)) echo "<p class='error-text'>$login_error</p>"; ?>
            <form method="POST" action="">
                <div class="input-field">
                    <input type="text" name="username" placeholder="Username" required>
                </div>
                <div class="input-field">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// --- IP RESTRICTION (after login) ---
// if (!in_array($_SERVER['REMOTE_ADDR'], $allowed_ips)) {
//     SecurityHelper::jsonError('Access denied: Your IP is not allowed.', 403);
// }

// --- INPUT VALIDATION FUNCTION ---

// --- PHP LOGIC ---
$controller = new DeleteController();
$controller->handleRequest();


// --- BACKUP BROWSER ENDPOINTS ---
$backupsDir = __DIR__ . '/backups';
if (!is_dir($backupsDir)) mkdir($backupsDir, 0755, true);
// List all backups and their contents
if (isset($_GET['list_backups']) && $_GET['list_backups'] == '1') {
    $backups = BackupManager::listBackups($backupsDir);
    SecurityHelper::jsonResponse(['backups' => $backups]);
    exit;
}
// Restore from backup browser
if (isset($_GET['restore_from_backup']) && $_GET['restore_from_backup'] == '1' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $backupDir = $_POST['backupDir'] ?? '';
    $item = $_POST['item'] ?? '';
    $result = BackupManager::restoreFromBackup($backupDir, $item, $backupsDir, $baseDir);
    if (isset($result['error'])) {
        SecurityHelper::jsonError($result);
    }
    SecurityHelper::jsonResponse($result);
    exit;
}
// Delete backup directory
if (isset($_GET['delete_backup']) && $_GET['delete_backup'] == '1' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $backupDir = $_POST['backupDir'] ?? '';
    $result = BackupManager::deleteBackup($backupDir, $backupsDir);
    if (isset($result['error'])) {
        SecurityHelper::jsonError($result);
    }
    SecurityHelper::jsonResponse($result);
    exit;
}

// --- Instantiate and run the controller ---
$controller = new DeleteController();
$controller->handleRequest();

// Clean up expired sessions periodically (every 10th request)
if (rand(1, 10) === 1) {
    SessionManager::cleanupExpiredSessions();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WordPress Tools Kit</title>
    
    <!-- Bootstrap 5.3.3 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome 6.5.1 -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    
    <!-- SweetAlert2 for modals -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/sweetalert2@11.10.5/dist/sweetalert2.min.css">
    
    <!-- Toastify for notifications -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/toastify-js@1.12.0/src/toastify.min.css">
    
    <!-- Style CSS -->
    <link rel="stylesheet" href="style.css">
    <style>
        /* Quick-navigation chips (self-contained so they render without style.css) */
        html { scroll-behavior: smooth; }
        [id$="Section"] { scroll-margin-top: 90px; }
        #toolNavSection {
            background: rgba(255,255,255,0.97);
            backdrop-filter: blur(4px);
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        .tool-nav-chip {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 20px;
            background: #eef2f7;
            color: #0073e6;
            font-size: 0.85rem;
            font-weight: 600;
            text-decoration: none;
            border: 1px solid #d7e2ef;
            transition: background 0.15s, color 0.15s, transform 0.1s;
        }
        .tool-nav-chip:hover {
            background: #0073e6;
            color: #fff;
            transform: translateY(-1px);
        }
        [data-theme="dark"] #toolNavSection { background: rgba(30,30,30,0.97); }
        [data-theme="dark"] .tool-nav-chip {
            background: #2a2a2a; color: #6cb6ff; border-color: #3a3a3a;
        }
        [data-theme="dark"] .tool-nav-chip:hover { background: #0073e6; color: #fff; }
    </style>
</head>
<body>
    <!-- Dark Mode Toggle -->
    <button class="dark-mode-toggle" onclick="toggleDarkMode()" title="Toggle Dark Mode">
        <i class="fas fa-moon"></i>
    </button>
    <div class="container">
        <!-- Presets Section -->
        <div class="section">
            <div class="section-header">
                <div class="section-title">
                    <i class="fas fa-cog section-icon"></i>
                    <h3>WordPress Tools Kit</h3>
                </div>
                
                <!-- Advanced Options Dropdown -->
                <div class="advanced-options">
                    <button class="dropdown-btn" onclick="toggleAdvancedOptions()">
                        <i class="fas fa-ellipsis-v"></i>
                    </button>
                    <div class="dropdown-menu" id="advancedDropdown">
                        <div class="dropdown-item" onclick="showAbout()">
                            <i class="fas fa-info-circle"></i>
                            About
                        </div>
                        <div class="dropdown-item" onclick="showOptionsModal()">
                            <i class="fas fa-sliders-h"></i>
                            Advanced Options
                        </div>
                        <a href="?logout=1" class="dropdown-item">
                            <i class="fas fa-sign-out-alt"></i>
                            Logout
                        </a>
                    </div>
                </div>
            </div>
        </div>

        <!-- Advanced Options (always visible, moved out of the popup modal) -->
        <div class="section">
            <div class="section-title" style="margin-bottom:10px;">
                <i class="fas fa-sliders-h section-icon"></i>
                <h3>Advanced Options</h3>
            </div>
            <div class="checkbox-group" id="inlineAdvancedOptions"
                 style="display:flex;flex-wrap:wrap;gap:20px;">
                <div class="checkbox-item" style="display:flex;align-items:center;gap:8px;">
                    <input type="checkbox" id="inlineBackup" style="width:16px;height:16px;">
                    <label for="inlineBackup" style="cursor:pointer;margin:0;">
                        <i class="fas fa-shield-alt"></i> Backup before delete
                    </label>
                </div>
                <div class="checkbox-item" style="display:flex;align-items:center;gap:8px;">
                    <input type="checkbox" id="inlineDryRun" style="width:16px;height:16px;">
                    <label for="inlineDryRun" style="cursor:pointer;margin:0;">
                        <i class="fas fa-play-circle"></i> Dry Run (pretend, do not delete)
                    </label>
                </div>
                <div class="checkbox-item" style="display:flex;align-items:center;gap:8px;">
                    <input type="checkbox" id="inlineSoftDelete" style="width:16px;height:16px;">
                    <label for="inlineSoftDelete" style="cursor:pointer;margin:0;">
                        <i class="fas fa-trash-restore"></i> Soft Delete
                    </label>
                </div>
            </div>
            <small style="color:#888;">Allowed: any single option, or Backup + Soft Delete together.</small>
        </div>

        <!-- Quick navigation to all tool sections -->
        <div class="section" id="toolNavSection" style="position:sticky;top:0;z-index:50;">
            <div class="section-title mb-2">
                <i class="fas fa-compass section-icon"></i>
                <h3>Quick Navigation</h3>
            </div>
            <div id="toolNav" style="display:flex;flex-wrap:wrap;gap:8px;">
                <a class="tool-nav-chip" href="#zipSection"><i class="fas fa-file-archive"></i> Zip</a>
                <a class="tool-nav-chip" href="#deleteSection"><i class="fas fa-trash"></i> Delete</a>
                <a class="tool-nav-chip" href="#backupsSection"><i class="fas fa-archive"></i> Backups</a>
                <a class="tool-nav-chip" href="#trashSection"><i class="fas fa-trash-restore"></i> Trash</a>
                <a class="tool-nav-chip" href="#malwareScannerSection"><i class="fas fa-bug"></i> Malware Scan</a>
                <a class="tool-nav-chip" href="#databaseCleanerSection"><i class="fas fa-database"></i> DB Cleaner</a>
                <a class="tool-nav-chip" href="#commandExecutorSection"><i class="fas fa-terminal"></i> Command</a>
                <a class="tool-nav-chip" href="#searchReplaceSection"><i class="fas fa-exchange-alt"></i> Search-Replace</a>
                <a class="tool-nav-chip" href="#adminUserSection"><i class="fas fa-user-shield"></i> Admin Users</a>
                <a class="tool-nav-chip" href="#dbExportSection"><i class="fas fa-file-export"></i> DB Export</a>
                <a class="tool-nav-chip" href="#integritySection"><i class="fas fa-fingerprint"></i> Integrity</a>
            </div>
        </div>

        <div class="section">
            <div><strong>Domain:</strong> <?php echo htmlspecialchars($_SERVER['HTTP_HOST'] ?? ''); ?></div>
            <div><strong>Current Path:</strong> <?php echo htmlspecialchars(getcwd()); ?></div>
        </div>

        <div class="section">
            <!-- Status Dashboard -->
            <div class="status-dashboard-header">
                <h4><i class="fas fa-chart-line"></i> Status Dashboard</h4>
                <div class="status-dashboard-controls">
                    <button class="btn btn-sm btn-outline" id="refreshStatus" title="Refresh Status">
                        <i class="fas fa-sync-alt"></i> Refresh
                    </button>
                    <label class="auto-refresh-toggle">
                        <input type="checkbox" id="autoRefresh" checked>
                        <span class="toggle-label">Auto-refresh</span>
                    </label>
                </div>
            </div>
            <div class="status-dashboard">
                <div class="status-card">
                    <i class="fas fa-hdd"></i>
                    <div class="status-info">
                        <h4>Disk Usage</h4>
                        <p id="diskUsage"><i class="fas fa-spinner fa-spin"></i> Loading...</p>
                        <div class="progress-bar">
                            <div class="progress-fill" id="diskProgress"></div>
                        </div>
                    </div>
                </div>
                <div class="status-card">
                    <i class="fas fa-archive"></i>
                    <div class="status-info">
                        <h4>Backups</h4>
                        <p id="backupCount"><i class="fas fa-spinner fa-spin"></i> Loading...</p>
                        <small id="backupSize">Size: calculating...</small>
                    </div>
                </div>
                <div class="status-card">
                    <i class="fas fa-trash"></i>
                    <div class="status-info">
                        <h4>Trash Items</h4>
                        <p id="trashCount"><i class="fas fa-spinner fa-spin"></i> Loading...</p>
                        <small id="trashSize">Size: calculating...</small>
                    </div>
                </div>
                <div class="status-card">
                    <i class="fas fa-file-archive"></i>
                    <div class="status-info">
                        <h4>ZIP Files</h4>
                        <p id="zipCount"><i class="fas fa-spinner fa-spin"></i> Loading...</p>
                        <small id="zipSize">Size: calculating...</small>
                    </div>
                </div>
                <div class="status-card">
                    <i class="fas fa-memory"></i>
                    <div class="status-info">
                        <h4>Memory Usage</h4>
                        <p id="memoryUsage"><i class="fas fa-spinner fa-spin"></i> Loading...</p>
                        <div class="progress-bar">
                            <div class="progress-fill" id="memoryProgress"></div>
                        </div>
                    </div>
                </div>

                <div class="status-card">
                    <i class="fas fa-shield-alt"></i>
                    <div class="status-info">
                        <h4>Security Status</h4>
                        <p id="securityStatus"><i class="fas fa-spinner fa-spin"></i> Loading...</p>
                        <small id="securityDetails">Checking...</small>
                    </div>
                </div>
                <div class="status-card">
                    <i class="fas fa-cogs"></i>
                    <div class="status-info">
                        <h4>PHP Version</h4>
                        <p id="phpVersion"><i class="fas fa-spinner fa-spin"></i> Loading...</p>
                        <small id="phpExtensions">Extensions: --</small>
                    </div>
                </div>
                <div class="status-card">
                    <i class="fas fa-folder"></i>
                    <div class="status-info">
                        <h4>Presets</h4>
                        <p id="presetCount"><i class="fas fa-spinner fa-spin"></i> Loading...</p>
                        <small id="presetInfo">Custom presets</small>
                    </div>
                </div>

            </div>
        </div>

        <!-- Action Buttons -->
        <div class="section">
            <div class="action-buttons">
                <button class="action-btn btn-green"  id="oneClickFixBtn">
                    <i class="fa-solid fa-hammer"></i> One Click Fix
                </button>
                <button class="action-btn btn btn-primary" id="systemHealthBtn">
                    <i class="fas fa-heartbeat"></i> System Health
                </button>
            </div>
        </div>

        <!-- Action Buttons -->
        <div class="section">
            <div class="action-buttons">
                <button class="action-btn btn-primary" id="downloadWPBtn">
                    <i class="fas fa-sync-alt"></i> Replace WordPress Cores
                </button>
                <button class="action-btn btn-light" id="checkPluginsBtn">
                    <i class="fas fa-search"></i> Update WordPress Plugins
                </button>
                <button class="action-btn btn-light" id="fixPermissionsBtn">
                    <i class="fas fa-shield-alt"></i> Fix Files Permissions
                </button>
                <button class="action-btn btn-primary" onclick="updateWordPressSalts()">
                    <i class="fas fa-key"></i> Update WordPress Salts
                </button>
                <span id="downloadWPStatus" class="status-text"></span>
                <span id="pluginUpdateStatus" class="status-text"></span>
            </div>
        </div>

        <!-- Zip Section -->
        <div class="section" id="zipSection">
            <div class="section-title">
                <i class="fas fa-file-archive section-icon"></i>
                <h3>Zip Files/Folders</h3>
            </div>
            
            <div class="form-group">
                <button type="button" class="btn btn-primary btn-lg" id="openZipBrowser">
                    📂 Browse & Select Files
                </button>
            </div>
            
            <div id="zipFilesArea" class="zip-files-area">
                <div class="zip-files-empty c-grey">No zip files found.</div>
            </div>
        </div>

        <div class="section" id="deleteSection">
            
            <div class="section-title mb-30">
                <i class="fas fa-trash section-icon"></i>
                <h3>Delete Files and Folders</h2>
            </div>
            <div class="form-group">
                <label class="form-label" for="presetSelect">Preset</label>
                <div class="input-group">
                    <select class="form-control" id="presetSelect">
                        <option value="">-- Select a preset --</option>
                        <option value="wp-core">WordPress Core Files</option>
                    </select>

                    <button type="file" class="btn btn-primary btn-md" id="importPresetBtn">
                        <i class="fa-solid fa-upload"></i></i> Import
                    </button>
                    <button class="btn btn-light btn-md" id="exportPresetBtn">
                        <i class="fa-solid fa-file-export"></i></i> Export
                    </button>
                    <button class="btn btn-danger btn-md" id="deletePresetBtn">
                        <i class="fas fa-trash"></i> Delete
                    </button>
                </div>
            </div>

            <div class="form-group" id="savePresetGroup">
                <label class="form-label" for="savePresetName">Preset Name</label>
                <div class="input-group">
                    <input type="text" class="form-control" id="savePresetName" placeholder="Enter preset name">
                    <button class="btn btn-primary btn-md" id="savePresetBtn">
                        <i class="fas fa-save"></i> Save as Preset
                    </button>
                </div>
            </div>
        </div>

        <form action="" method="POST" id="deleteForm" autocomplete="off">
            <!-- Delete Folders Section -->
            <div class="section">
                <div class="section-title">
                    <i class="fas fa-folder section-icon"></i>
                    <h3>Delete Folders</h3>
                </div>
                
                <div class="input-group">
                    <input type="text" name="folders[]" class="form-control" id="folderPath" 
                        placeholder="Enter folder path relative to this directory (e.g., subdir)">
                    <button type="button" class="btn btn-light btn-md" onclick="browseFolders()" tile="Open Browse">
                        <i class="fas fa-folder-open"></i>
                    </button>

                    <button type="button" id="addFolderField" class="btn btn-outline btn-md" onclick="addFolder()" tile="Add Folder">
                        <i class="fas fa-plus"></i>
                    </button>
                </div>
                
                <div class="folder-list" id="folderList"></div>
            </div>

            <!-- Delete Files Section -->
            <div class="section">
                <div class="section-title">
                    <i class="fas fa-file section-icon"></i>
                    <h3>Delete Files</h3>
                </div>
                
                <div class="input-group">
                    <input type="text" name="files[]" class="form-control" id="filePath" 
                        placeholder="Enter file path relative to this directory (e.g., file.php)">
                    <button type="button" class="btn btn-light btn-md" onclick="browseFiles()">
                        <i class="fas fa-file-alt"></i>
                    </button>

                    <button type="button" id="addFileField"  class="btn btn-outline btn-md" onclick="addFile()">
                        <i class="fas fa-plus"></i>
                    </button>
                </div>
                
                <div class="file-list" id="fileList"></div>
            </div>

            <!-- Delete Button -->
            <div class="section delete-section">
                <button type="submit" class="delete-btn">
                    <i class="fas fa-trash-alt"></i> Delete
                </button>
            </div>
        </form>

        <!-- Backups Section -->
        <div class="section" id="backupsSection">
            <div class="section-title">
                <i class="fas fa-archive section-icon"></i>
                <h3>Backups</h3>
            </div>
            <div id="backupsList"><i class="fas fa-spinner fa-spin"></i> Loading...</div>
        </div>

        <!-- Trash Section -->
        <div class="section" id="trashSection">
            <div class="section-title">
                <i class="fas fa-trash section-icon"></i>
                <h3>Trash</h3>
            </div>
            <div id="trashList"><i class="fas fa-spinner fa-spin"></i> Loading...</div>
        </div>

        <!-- ============================================================
             MALWARE SCANNER SECTION
             ============================================================ -->
        <div class="section" id="malwareScannerSection">
            <div class="section-title mb-30">
                <i class="fas fa-bug section-icon"></i>
                <h3>Malware Scanner</h3>
            </div>

            <div class="form-row mb-3" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
                <div class="form-group" style="margin:0;">
                    <label class="form-label">Scan Root Directory</label>
                    <input type="text" class="form-control" id="scanRootDir" value="" placeholder="Leave empty to auto-detect">
                    <small class="form-text c-grey">Defaults to WordPress root (where wp-config.php is). Leave blank to auto-detect.</small>
                </div>
                <div class="form-group" style="margin:0;">
                    <label class="form-label">Exclude Paths (one per line)</label>
                    <textarea class="form-control" id="scanExcludePaths" rows="2" placeholder="wp-admin&#10;wp-includes&#10;.git&#10;node_modules"></textarea>
                    <small class="form-text c-grey">Folders/files to skip during scan</small>
                </div>
            </div>

            <div class="action-buttons" style="grid-template-columns:repeat(3,1fr);">
                <button class="action-btn btn-danger" id="startMalwareScanBtn">
                    <i class="fas fa-search"></i> Scan for Malware
                </button>
                <button class="action-btn btn-primary" id="listQuarantineBtn">
                    <i class="fas fa-shield-virus"></i> View Quarantine
                </button>
                <button class="action-btn btn-light" id="emptyQuarantineBtn">
                    <i class="fas fa-broom"></i> Empty Quarantine
                </button>
            </div>

            <div id="malwareScanResults" style="margin-top:18px;"></div>
        </div>

        <!-- ============================================================
             DATABASE CLEANER SECTION
             ============================================================ -->
        <div class="section" id="databaseCleanerSection">
            <div class="section-title mb-30">
                <i class="fas fa-database section-icon"></i>
                <h3>Database Cleaner</h3>
            </div>
            <p class="c-grey mb-3">Scan and clean WordPress database bloat: transients, revisions, spam comments, orphaned metadata, and autoload options.</p>
            <div class="action-buttons" style="grid-template-columns:repeat(2,1fr);">
                <button class="action-btn btn-primary" id="dbScanBtn">
                    <i class="fas fa-search"></i> Scan Database
                </button>
                <button class="action-btn btn-light" id="dbOptimizeBtn" style="display:none;">
                    <i class="fas fa-broom"></i> Optimize Tables
                </button>
            </div>
            <div id="dbScanSummary" style="margin-top:18px;"></div>
            <div id="dbCategoryTabs" style="display:none; margin-top:18px;">
                <ul class="nav nav-tabs" id="dbTabNav" role="tablist"></ul>
                <div class="tab-content mt-3" id="dbTabContent"></div>
            </div>
        </div>

        <!-- ============================================================
             COMMAND EXECUTOR SECTION
             ============================================================ -->
        <div class="section" id="commandExecutorSection">
            <div class="section-title mb-30">
                <i class="fas fa-terminal section-icon"></i>
                <h3>Command Executor</h3>
            </div>
            <p class="c-grey mb-3">Execute safe diagnostic commands on the server. Only read-only commands are allowed — no destructive operations.</p>
            <div class="form-group" style="margin-bottom:12px;">
                <label class="form-label">Command</label>
                <div class="input-group">
                    <input type="text" class="form-control" id="cmdInput" placeholder='e.g. find . -name "*.php" | head -20' style="font-family:monospace;">
                    <button class="btn btn-primary" id="runCmdBtn"><i class="fas fa-play"></i> Run</button>
                </div>
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
                <button class="btn btn-sm btn-outline-secondary cmd-preset" data-cmd="find . -name '*.php' | head -20">Find PHP files</button>
                <button class="btn btn-sm btn-outline-secondary cmd-preset" data-cmd="ls -lah">List directory</button>
                <button class="btn btn-sm btn-outline-secondary cmd-preset" data-cmd="df -h">Disk usage</button>
                <button class="btn btn-sm btn-outline-secondary cmd-preset" data-cmd="php -v">PHP version</button>
                <button class="btn btn-sm btn-outline-secondary cmd-preset" data-cmd="whoami">Current user</button>
                <button class="btn btn-sm btn-outline-secondary cmd-preset" data-cmd="uptime">Server uptime</button>
            </div>
            <div id="cmdOutput" style="display:none;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                    <strong id="cmdExecuted">Command:</strong>
                    <button class="btn btn-sm btn-outline-secondary" id="copyCmdOutput"><i class="fas fa-copy"></i> Copy</button>
                </div>
                <pre id="cmdOutputBox" style="background:#1e1e1e;color:#d4d4d4;padding:16px;border-radius:8px;max-height:400px;overflow:auto;font-size:.85rem;white-space:pre-wrap;word-break:break-all;"></pre>
            </div>
        </div>

        <!-- ============================================================
             DATABASE SEARCH-REPLACE SECTION
             ============================================================ -->
        <div class="section" id="searchReplaceSection">
            <div class="section-title mb-30">
                <i class="fas fa-exchange-alt section-icon"></i>
                <h3>Database Search &amp; Replace</h3>
            </div>
            <p class="c-grey mb-3">Serialization-safe find &amp; replace across all database tables (e.g. change a domain after migration). Always run a <strong>Dry Run</strong> first, and back up the database before applying.</p>
            <div class="form-group" style="margin-bottom:10px;">
                <label class="form-label">Search for</label>
                <input type="text" class="form-control" id="srSearch" placeholder="https://old-domain.com">
            </div>
            <div class="form-group" style="margin-bottom:10px;">
                <label class="form-label">Replace with</label>
                <input type="text" class="form-control" id="srReplace" placeholder="https://new-domain.com">
            </div>
            <div class="checkbox-item" style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
                <input type="checkbox" id="srDryRun" checked style="width:16px;height:16px;">
                <label for="srDryRun" style="cursor:pointer;margin:0;">Dry Run (count changes, do not write)</label>
            </div>
            <div class="action-buttons" style="grid-template-columns:repeat(2,1fr);">
                <button class="action-btn btn-primary" id="srRunBtn"><i class="fas fa-play"></i> Run Search-Replace</button>
            </div>
            <div id="srResults" style="margin-top:16px;"></div>
        </div>

        <!-- ============================================================
             ADMIN USER MANAGER SECTION
             ============================================================ -->
        <div class="section" id="adminUserSection">
            <div class="section-title mb-30">
                <i class="fas fa-user-shield section-icon"></i>
                <h3>Admin User Manager</h3>
            </div>
            <p class="c-grey mb-3">List administrators, reset a password, or create a new admin — useful for regaining access when locked out of wp-admin.</p>
            <div class="action-buttons" style="grid-template-columns:repeat(2,1fr);">
                <button class="action-btn btn-light" id="wpListAdminsBtn"><i class="fas fa-users"></i> List Admins</button>
                <button class="action-btn btn-primary" id="wpCreateAdminBtn"><i class="fas fa-user-plus"></i> Create Admin</button>
            </div>
            <div id="wpAdminsList" style="margin-top:16px;"></div>
        </div>

        <!-- ============================================================
             DATABASE EXPORT / BACKUP SECTION
             ============================================================ -->
        <div class="section" id="dbExportSection">
            <div class="section-title mb-30">
                <i class="fas fa-file-export section-icon"></i>
                <h3>Database Backup / Export</h3>
            </div>
            <p class="c-grey mb-3">Export the entire WordPress database to a downloadable <code>.sql</code> file (structure + data), processed table-by-table so large databases don't time out.</p>
            <div class="action-buttons" style="grid-template-columns:repeat(2,1fr);">
                <button class="action-btn btn-primary" id="dbExportBtn"><i class="fas fa-download"></i> Export Database</button>
            </div>
            <div id="dbExportResults" style="margin-top:16px;"></div>
        </div>

        <!-- ============================================================
             CORE INTEGRITY CHECKER SECTION
             ============================================================ -->
        <div class="section" id="integritySection">
            <div class="section-title mb-30">
                <i class="fas fa-fingerprint section-icon"></i>
                <h3>Core Integrity Checker</h3>
            </div>
            <p class="c-grey mb-3">Verify <code>wp-admin</code>, <code>wp-includes</code>, and root core files against official WordPress.org checksums to detect injected or modified core files.</p>
            <div class="action-buttons" style="grid-template-columns:repeat(2,1fr);">
                <button class="action-btn btn-primary" id="integrityBtn"><i class="fas fa-shield-virus"></i> Check Core Integrity</button>
            </div>
            <div id="integrityResults" style="margin-top:16px;"></div>
        </div>
    </div>

    <!-- jQuery 3.7.1 -->
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    
    <!-- Bootstrap 5.3.3 JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- SweetAlert2 -->
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11.10.5/dist/sweetalert2.all.min.js"></script>
    
    <!-- Toastify -->
    <script src="https://cdn.jsdelivr.net/npm/toastify-js@1.12.0"></script>

    <script>
        // Dark mode toggle
        function toggleDarkMode() {
            const body = document.body;
            const currentTheme = body.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            body.setAttribute('data-theme', newTheme);
            localStorage.setItem('wpToolsTheme', newTheme);
            
            const icon = document.querySelector('.dark-mode-toggle i');
            icon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }

        // Function to check if there are items selected and show/hide delete section
        function updateDeleteSectionVisibility() {
            const folderItems = $('#folderList .folder-item').length;
            const fileItems = $('#fileList .file-item').length;
            const totalItems = folderItems + fileItems;
            
            const deleteSection = $('.delete-section');
            if (totalItems > 0) {
                deleteSection.addClass('has-items');
            } else {
                deleteSection.removeClass('has-items');
            }
        }
        
        // Restore on page load
        $(document).ready(function() {
            // Auto-detect WordPress root for malware scanner
            $.get('?detect_wp_root=1', function(resp) {
                if (resp.root) {
                    $('#scanRootDir').val(resp.root);
                }
            }, 'json').fail(() => {});

            restoreFormData();
            loadStatusDashboard();
            updateDeleteSectionVisibility(); // Check initial state
        });

        // Auto-save functionality
        let autoSaveTimer;
        
        function autoSave() {
            const formData = {
                folders: $('#folderList').html(),
                files: $('#fileList').html(),
                presetName: $('#savePresetName').val()
            };
            localStorage.setItem('wpToolsFormData', JSON.stringify(formData));
        }
        
        function restoreFormData() {
            const saved = localStorage.getItem('wpToolsFormData');
            if (saved) {
                const data = JSON.parse(saved);
                $('#folderList').html(data.folders || '');
                $('#fileList').html(data.files || '');
                $('#savePresetName').val(data.presetName || '');
            }
        }
        
        // Auto-save on form changes
        $(document).on('input change', '#folderPath, #filePath, #savePresetName', function() {
            clearTimeout(autoSaveTimer);
            autoSaveTimer = setTimeout(autoSave, 1000);
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'b') {
                e.preventDefault();
                openZipBrowser();
            }
            if (e.ctrlKey && e.key === 'd') {
                e.preventDefault();
                executeDelete();
            }
            if (e.ctrlKey && e.key === 'f') {
                e.preventDefault();
                $('#globalSearch').focus();
            }
            if (e.ctrlKey && e.key === 's') {
                e.preventDefault();
                $('#savePresetBtn').click();
            }
        });
        
        // Load saved theme
        const savedTheme = localStorage.getItem('wpToolsTheme');
        if (savedTheme) {
            document.body.setAttribute('data-theme', savedTheme);
            const icon = document.querySelector('.dark-mode-toggle i');
            icon.className = savedTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }

        // Cache for dashboard data to prevent duplicate calls
        let dashboardCache = {
            systemHealth: null,
            backups: null,
            trash: null,
            zips: null,
            presets: null,
            lastUpdate: 0,
            cacheTimeout: 30000 // 30 seconds cache
        };
        
        // Force initial load by clearing cache
        function clearDashboardCache() {
            dashboardCache.systemHealth = null;
            dashboardCache.backups = null;
            dashboardCache.trash = null;
            dashboardCache.zips = null;
            dashboardCache.presets = null;
            dashboardCache.lastUpdate = 0;
        }
        
        // Status dashboard with caching
        function loadStatusDashboard() {
            const now = Date.now();
            const cacheValid = (now - dashboardCache.lastUpdate) < dashboardCache.cacheTimeout;
            
            // Use cached data if available and valid
            if (cacheValid && dashboardCache.systemHealth && dashboardCache.backups && dashboardCache.trash && dashboardCache.zips && dashboardCache.presets) {
                updateStatusDashboardFromCache();
                return;
            }
            
            // Single system health call to get all system data
            $.get('?system_health=1', function(response) {
                dashboardCache.systemHealth = response;
                dashboardCache.lastUpdate = now;
                
                if (response.report) {
                    // Load disk usage
                    if (response.report.disk) {
                        const used = response.report.disk.used_space || '0 B';
                        const total = response.report.disk.total_space || '0 B';
                        const percentage = response.report.disk.usage_percentage || 0;
                        
                        $('#diskUsage').html(used + ' / ' + total);
                        $('#diskProgress').css('width', percentage + '%');
                        
                        // Color coding based on usage
                        const diskCard = $('#diskUsage').closest('.status-card');
                        diskCard.removeClass('success warning danger');
                        if (percentage > 90) {
                            diskCard.addClass('danger');
                        } else if (percentage > 75) {
                            diskCard.addClass('warning');
                        } else {
                            diskCard.addClass('success');
                        }
                    } else {
                        $('#diskUsage').html('Unknown');
                        $('#diskProgress').css('width', '0%');
                    }
                    
                    // Load memory usage
                    if (response.report.memory) {
                        const used = response.report.memory.current_usage || '0 B';
                        const limit = response.report.memory.memory_limit || '0 B';
                        const percentage = response.report.memory.usage_percentage || 0;
                        
                        $('#memoryUsage').html(used + ' / ' + limit);
                        $('#memoryProgress').css('width', percentage + '%');
                        
                        // Color coding based on memory usage
                        const memoryCard = $('#memoryUsage').closest('.status-card');
                        memoryCard.removeClass('success warning danger');
                        if (percentage > 90) {
                            memoryCard.addClass('danger');
                        } else if (percentage > 75) {
                            memoryCard.addClass('warning');
                        } else {
                            memoryCard.addClass('success');
                        }
                    } else {
                        $('#memoryUsage').html('Unknown');
                        $('#memoryProgress').css('width', '0%');
                    }
                    
                    // Load security status
                    if (response.report.security) {
                        const issues = response.report.security.issues || [];
                        const status = issues.length === 0 ? 'Secure' : 'Issues Found';
                        
                        $('#securityStatus').html(status);
                        $('#securityDetails').text(issues.length > 0 ? issues.length + ' issues' : 'No issues');
                        
                        // Color coding based on security status
                        const securityCard = $('#securityStatus').closest('.status-card');
                        securityCard.removeClass('success warning danger');
                        if (issues.length > 5) {
                            securityCard.addClass('danger');
                        } else if (issues.length > 0) {
                            securityCard.addClass('warning');
                        } else {
                            securityCard.addClass('success');
                        }
                    } else {
                        $('#securityStatus').html('Unknown');
                        $('#securityDetails').text('Status unavailable');
                    }
                    
                    // Load PHP version and extensions
                    if (response.report.system) {
                        $('#phpVersion').html(response.report.system.php_version || 'Unknown');
                        const extensions = response.report.system.php_extensions || [];
                        $('#phpExtensions').text('Extensions: ' + extensions.length);
                    } else {
                        $('#phpVersion').html('Unknown');
                        $('#phpExtensions').text('Extensions: --');
                    }
                } else {
                    // Handle missing report data
                    $('#diskUsage').html('Unknown');
                    $('#diskProgress').css('width', '0%');
                    $('#memoryUsage').html('Unknown');
                    $('#memoryProgress').css('width', '0%');
                    $('#securityStatus').html('Unknown');
                    $('#securityDetails').text('Status unavailable');
                    $('#phpVersion').html('Unknown');
                    $('#phpExtensions').text('Extensions: --');
                }
                
                // Load other data in parallel
                loadDashboardData();
                
            }).fail(function(xhr, status, error) {
                $('#diskUsage').html('Error loading');
                $('#diskProgress').css('width', '0%');
                $('#memoryUsage').html('Error loading');
                $('#memoryProgress').css('width', '0%');
                $('#securityStatus').html('Error loading');
                $('#securityDetails').text('Failed to load');
                $('#phpVersion').html('Error loading');
                $('#phpExtensions').text('Extensions: --');
            });
        }
        
        // Load other dashboard data (backups, trash, zips, presets)
        function loadDashboardData() {
            // Use cached data if available and valid
            const now = Date.now();
            const cacheValid = (now - dashboardCache.lastUpdate) < dashboardCache.cacheTimeout;
            
            if (cacheValid && dashboardCache.backups && dashboardCache.trash && dashboardCache.zips && dashboardCache.presets) {
                updateBackupDisplay(dashboardCache.backups);
                updateTrashDisplay(dashboardCache.trash);
                updateZipDisplay(dashboardCache.zips);
                updatePresetDisplay(dashboardCache.presets);
                return;
            }
            
            // Load all data in parallel with individual error handling
            let completedRequests = 0;
            let totalRequests = 4;
            
            function checkAllRequestsComplete() {
                completedRequests++;
                if (completedRequests === totalRequests) {
                    dashboardCache.lastUpdate = now;
                }
            }
            
            // Load backups
            $.get('?list_backups=1')
                .done(function(response) {
                    dashboardCache.backups = response;
                    updateBackupDisplay(response);
                })
                .fail(function() {
                    $('#backupCount').html('Error loading');
                    $('#backupSize').text('Failed to load');
                })
                .always(function() {
                    checkAllRequestsComplete();
                });
            
            // Load trash
            $.get('?list_trash=1')
                .done(function(response) {
                    dashboardCache.trash = response;
                    updateTrashDisplay(response);
                })
                .fail(function() {
                    $('#trashCount').html('Error loading');
                    $('#trashSize').text('Failed to load');
                })
                .always(function() {
                    checkAllRequestsComplete();
                });
            
            // Load zips
            $.get('?list_zips=1')
                .done(function(response) {
                    dashboardCache.zips = response;
                    updateZipDisplay(response);
                })
                .fail(function() {
                    $('#zipCount').html('Error loading');
                    $('#zipSize').text('Failed to load');
                })
                .always(function() {
                    checkAllRequestsComplete();
                });
            
            // Load presets
            $.get('?list_presets=1')
                .done(function(response) {
                    dashboardCache.presets = response;
                    updatePresetDisplay(response);
                })
                .fail(function() {
                    $('#presetCount').html('Error loading');
                    $('#presetInfo').text('Failed to load');
                })
                .always(function() {
                    checkAllRequestsComplete();
                });
        }
        
        // Update functions for each data type
        function updateBackupDisplay(response) {
            if (response.backups) {
                const totalItems = response.backups.reduce((total, backup) => total + (backup.items ? backup.items.length : 0), 0);
                $('#backupCount').html(response.backups.length + ' available');
                $('#backupSize').text('Total items: ' + totalItems);
            } else {
                $('#backupCount').html('0 available');
                $('#backupSize').text('No backups');
            }
        }
        
        function updateTrashDisplay(response) {
            if (response.items) {
                const totalSize = response.items.reduce((total, item) => total + (parseInt(item.size) || 0), 0);
                $('#trashCount').html(response.items.length + ' items');
                $('#trashSize').text('Size: ' + formatBytes(totalSize));
            } else {
                $('#trashCount').html('0 items');
                $('#trashSize').text('Empty trash');
            }
        }
        
        function updateZipDisplay(response) {
            if (response.zips) {
                const totalSize = response.zips.reduce((total, zip) => total + (parseInt(zip.size) || 0), 0);
                $('#zipCount').html(response.zips.length + ' files');
                $('#zipSize').text('Size: ' + formatBytes(totalSize));
            } else {
                $('#zipCount').html('0 files');
                $('#zipSize').text('No ZIP files');
            }
        }
        
        function updatePresetDisplay(response) {
            if (response.presets) {
                $('#presetCount').html(response.presets.length + ' presets');
                $('#presetInfo').text(response.presets.length > 0 ? 'Custom presets' : 'No custom presets');
            } else {
                $('#presetCount').html('0 presets');
                $('#presetInfo').text('No custom presets');
            }
        }
        
        // Function to update dashboard from cache
        function updateStatusDashboardFromCache() {
            if (dashboardCache.systemHealth) {
                const response = dashboardCache.systemHealth;
                if (response.report) {
                    // Update system health data from cache
                    if (response.report.disk) {
                        const used = response.report.disk.used_space || '0 B';
                        const total = response.report.disk.total_space || '0 B';
                        const percentage = response.report.disk.usage_percentage || 0;
                        $('#diskUsage').html(used + ' / ' + total);
                        $('#diskProgress').css('width', percentage + '%');
                    }
                    if (response.report.memory) {
                        const used = response.report.memory.current_usage || '0 B';
                        const limit = response.report.memory.memory_limit || '0 B';
                        const percentage = response.report.memory.usage_percentage || 0;
                        $('#memoryUsage').html(used + ' / ' + limit);
                        $('#memoryProgress').css('width', percentage + '%');
                    }
                    if (response.report.security) {
                        const issues = response.report.security.issues || [];
                        const status = issues.length === 0 ? 'Secure' : 'Issues Found';
                        $('#securityStatus').html(status);
                        $('#securityDetails').text(issues.length > 0 ? issues.length + ' issues' : 'No issues');
                    }
                    if (response.report.system) {
                        $('#phpVersion').html(response.report.system.php_version || 'Unknown');
                        const extensions = response.report.system.php_extensions || [];
                        $('#phpExtensions').text('Extensions: ' + extensions.length);
                    }
                }
            }
            
            // Update other data from cache
            if (dashboardCache.backups) updateBackupDisplay(dashboardCache.backups);
            if (dashboardCache.trash) updateTrashDisplay(dashboardCache.trash);
            if (dashboardCache.zips) updateZipDisplay(dashboardCache.zips);
            if (dashboardCache.presets) updatePresetDisplay(dashboardCache.presets);
        }
        
        // Utility function to format bytes
        function formatBytes(bytes) {
            // Handle invalid input
            if (!bytes || isNaN(bytes) || bytes < 0) return '0 B';
            
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        $(document).ready(function() {
            // --- Ensure all AJAX requests are recognized as AJAX by backend ---
            $.ajaxSetup({
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            
            // --- Status Dashboard Auto-refresh ---
            let autoRefreshInterval;
            
            function startAutoRefresh() {
                if (autoRefreshInterval) {
                    clearInterval(autoRefreshInterval);
                }
                autoRefreshInterval = setInterval(loadStatusDashboard, 60000); // Refresh every 60 seconds
            }
            
            function stopAutoRefresh() {
                if (autoRefreshInterval) {
                    clearInterval(autoRefreshInterval);
                    autoRefreshInterval = null;
                }
            }
            
            // Initialize auto-refresh
            startAutoRefresh();
            
            // Clear cache and initialize status dashboard
            clearDashboardCache();
            loadStatusDashboard();
            
            // Add tooltips to status cards
            $('.status-card').each(function() {
                const card = $(this);
                const title = card.find('h4').text();
                const info = card.find('p').text();
                const details = card.find('small').text();
                
                card.attr('title', `${title}\n${info}\n${details}`);
            });
            
            // Manual refresh button
            $('#refreshStatus').on('click', function() {
                const btn = $(this);
                const icon = btn.find('i');
                
                // Add loading state
                btn.prop('disabled', true);
                icon.addClass('fa-spin');
                
                loadStatusDashboard();
                
                // Remove loading state after a short delay
                setTimeout(() => {
                    btn.prop('disabled', false);
                    icon.removeClass('fa-spin');
                }, 1000);
            });
            
            // Auto-refresh toggle
            $('#autoRefresh').on('change', function() {
                if (this.checked) {
                    startAutoRefresh();
                } else {
                    stopAutoRefresh();
                }
            });

            // --- State ---
            let folders = [];
            let files = [];
            let options = { backup: false, dryRun: false, softDelete: false };

            // Valid combos: any single option, Backup+SoftDelete, or none.
            function isValidOptionCombo(backup, dryRun, softDelete) {
                return (dryRun && !backup && !softDelete)
                    || (backup && !dryRun && !softDelete)
                    || (softDelete && !dryRun && !backup)
                    || (backup && softDelete && !dryRun)
                    || (!backup && !dryRun && !softDelete);
            }

            // Reflect the current `options` state onto the inline checkboxes.
            function syncInlineOptionsUI() {
                $('#inlineBackup').prop('checked', options.backup);
                $('#inlineDryRun').prop('checked', options.dryRun);
                $('#inlineSoftDelete').prop('checked', options.softDelete);
            }

            // The Advanced Options are now always visible in the page body. Wire the
            // inline checkboxes so they update `options` live, enforcing the same
            // combination rules the popup modal used.
            $(function () {
                syncInlineOptionsUI();
                $('#inlineAdvancedOptions').on('change', 'input[type="checkbox"]', function () {
                    const backup = $('#inlineBackup').is(':checked');
                    const dryRun = $('#inlineDryRun').is(':checked');
                    const softDelete = $('#inlineSoftDelete').is(':checked');

                    if (!isValidOptionCombo(backup, dryRun, softDelete)) {
                        showNotification('Any single option, or Backup + Soft Delete.', 'error');
                        syncInlineOptionsUI(); // revert the invalid change
                        return;
                    }
                    options.backup = backup;
                    options.dryRun = dryRun;
                    options.softDelete = softDelete;
                });
            });

            // --- Utility: Show notification ---
            function showNotification(message, type = 'success') {
                if (typeof Toastify === 'undefined') {
                    return;
                }
                
                // Ensure message is a string
                let messageStr = '';
                if (typeof message === 'string') {
                    messageStr = message;
                } else if (message && typeof message.toString === 'function') {
                    messageStr = message.toString();
                } else {
                    messageStr = 'Unknown error';
                }
                
                const bgColors = {
                    success: 'linear-gradient(135deg, #00b09b, #96c93d)',
                    error: 'linear-gradient(135deg, #ff6b6b, #ee5a52)',
                    info: 'linear-gradient(135deg, #667eea, #764ba2)'
                };
                
                const cleanMessage = messageStr.replace(/<[^>]*>/g, '');
                
                Toastify({
                    text: cleanMessage,
                    duration: 3000,
                    gravity: "top",
                    position: "right",
                    style: {
                        background: bgColors[type] || bgColors.success,
                        color: '#fff',
                        'word-wrap': 'break-word',
                        'white-space': 'pre-wrap',
                        'max-width': '300px'
                    },
                    close: true
                }).showToast();
            }
            // Expose to global scope so standalone script blocks (WP Toolkit) can reuse it.
            window.showNotification = showNotification;

            // --- PRESETS: List, Load, Save, Delete ---
            const defaultPresets = {
                'wp-core': {
                    folders: [
                        'wp-admin',
                        'wp-includes'
                    ],
                    files: [
                        'index.php',
                        'license.txt',
                        'readme.html',
                        'wp-blog-header.php',
                        'wp-activate.php',
                        'wp-comments-post.php',
                        'wp-config-sample.php',
                        'wp-cron.php',
                        'wp-links-opml.php',
                        'wp-load.php',
                        'wp-login.php',
                        'wp-mail.php',
                        'wp-settings.php',
                        'wp-signup.php',
                        'wp-trackback.php',
                        'xmlrpc.php',
                        'wp-salt.php',
                        'wp-cli.yml'
                    ]
                }
            };

            // On page load, fetch root file list and add any wp-*.LCK files to defaultPresets['wp-core'].files
            $.get('?listdir=1&dir=', function(resp) {
                if (resp && resp.items) {
                    resp.items.forEach(function(item) {
                        if (item.type === 'file' && item.name.startsWith('wp-') && item.name.endsWith('.LCK')) {
                            if (!defaultPresets['wp-core'].files.includes(item.name)) {
                                defaultPresets['wp-core'].files.push(item.name);
                            }
                        }
                    });
                }
            });

            function refreshPresets() {
                // Use cached data if available
                if (dashboardCache.presets && dashboardCache.presets.presets) {
                    updatePresetDropdown(dashboardCache.presets.presets);
                    return;
                }
                
                let $presetSelect = $('#presetSelect');
                $presetSelect.empty();
                $presetSelect.append('<option value="">-- Select a preset --</option>');
                // Always add wp-core first
                $presetSelect.append('<option value="wp-core">WordPress core files</option>');
                $.get('?list_presets=1', function(data) {
                    dashboardCache.presets = data;
                    let presets = data.presets || [];
                    presets.forEach(function(name) {
                        if (name !== 'wp-core') {
                            $presetSelect.append('<option value="'+name+'">'+name+'</option>');
                        }
                    });
                });
            }
            
            function updatePresetDropdown(presets) {
                let $presetSelect = $('#presetSelect');
                $presetSelect.empty();
                $presetSelect.append('<option value="">-- Select a preset --</option>');
                $presetSelect.append('<option value="wp-core">WordPress core files</option>');
                
                presets.forEach(function(name) {
                    if (name !== 'wp-core') {
                        $presetSelect.append('<option value="'+name+'">'+name+'</option>');
                    }
                });
            }
            refreshPresets();

            $('#presetSelect').on('change', function() {
                let name = $(this).val();
                if (!name) return;
                if (name === 'wp-core') {
                    // Load from defaultPresets
                    let preset = defaultPresets['wp-core'];
                    folders = preset.folders.slice();
                    files = preset.files.slice();
                    updateFolderList();
                    updateFileList();
                    updateDeleteSectionVisibility();
                    $('#deletePresetBtn').prop('disabled', true);
                    showNotification('Preset loaded', 'success');
                    return;
                } else {
                    $('#deletePresetBtn').prop('disabled', false);
                }
                $.get('?load_preset=' + encodeURIComponent(name), function(data) {
                    try {
                        let preset = typeof data === 'string' ? JSON.parse(data) : data;
                        folders = preset.folders || [];
                        files = preset.files || [];
                        options = preset.options || options;
                        updateFolderList();
                        updateFileList();
                        updateDeleteSectionVisibility();
                        showNotification('Preset loaded', 'success');
                    } catch (e) {
                        showNotification('Failed to load preset', 'error');
                    }
                });
            });

            $('#savePresetBtn').on('click', function() {
                let name = $('#savePresetName').val().trim();
                if (!name) return showNotification('Enter a preset name', 'error');
                if (name === 'wp-core') return showNotification('Cannot overwrite default preset', 'error');
                let data = JSON.stringify({ folders, files, options });
                // Backend will store as JSON file
                $.post('?save_preset=1', { name, data }, function(resp) {
                    if (resp.success) {
                        // Invalidate cache and refresh presets
                        dashboardCache.presets = null;
                        refreshPresets();
                        
                        // Select the newly saved preset
                        setTimeout(() => {
                            $('#presetSelect').val(name).trigger('change');
                        }, 100);
                        
                        $('#savePresetName').val(''); // Clear input
                        $('#openPresetGroup').hide(); // Show open button
                        $('#closePresetGroup').show(); // Hide close button
                        $('#savePresetBtn').prop('disabled', true); // Disable save button
                        // Show success notification
                        showNotification('Preset saved and selected', 'success');
                    } else {
                        showNotification('Failed to save preset', 'error');
                    }
                });
            });

            $('#deletePresetBtn').on('click', function() {
                let name = $('#presetSelect').val();
                if (!name) return showNotification('Select a preset to delete', 'error');
                if (name === 'wp-core') return showNotification('Cannot delete default preset', 'error');
                $.post('?delete_preset=1', { name }, function(resp) {
                    if (resp.success) {
                        showNotification('Preset deleted', 'success');
                        // Invalidate cache and refresh presets
                        dashboardCache.presets = null;
                        refreshPresets();
                    } else {
                        showNotification('Failed to delete preset', 'error');
                    }
                });
            });

            // Preset group toggle functionality
            $('#openPresetGroup').on('click', function() {
                $(this).hide();
                $('#closePresetGroup').show();
                $('#savePresetGroup').slideDown();
            });

            $('#closePresetGroup').on('click', function() {
                $(this).hide();
                $('#openPresetGroup').show();
                $('#savePresetGroup').slideUp();
            });

            // Initially hide the close button
            $('#closePresetGroup').hide();

            // Export preset functionality
            $('#exportPresetBtn').on('click', function() {
                let name = $('#presetSelect').val();
                if (!name) return showNotification('Select a preset to export', 'error');
                
                // Get the preset data
                if (name === 'wp-core') {
                    // For wp-core, use the default preset
                    const presetData = defaultPresets['wp-core'];
                    downloadPreset(name, presetData);
                } else {
                    // For custom presets, load from server
                    $.get('?load_preset=' + encodeURIComponent(name))
                        .done(function(data) {
                            try {
                                const presetData = typeof data === 'string' ? JSON.parse(data) : data;
                                downloadPreset(name, presetData);
                            } catch (e) {
                                showNotification('Failed to parse preset data', 'error');
                            }
                        })
                        .fail(function() {
                            showNotification('Failed to load preset', 'error');
                        });
                }
                
                function downloadPreset(name, presetData) {
                    const blob = new Blob([JSON.stringify(presetData, null, 2)], { type: 'application/json' });
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    a.download = name + '-preset.json';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    window.URL.revokeObjectURL(url);
                                            showNotification('Preset exported successfully', 'success');
                }
            });

            // Import preset functionality
            $('#importPresetBtn').on('click', function() {
                // Create a hidden file input
                const fileInput = document.createElement('input');
                fileInput.type = 'file';
                fileInput.accept = '.json';
                fileInput.style.display = 'none';
                document.body.appendChild(fileInput);

                fileInput.onchange = function(e) {
                    const file = e.target.files[0];
                    if (!file) return;

                    const reader = new FileReader();
                    reader.onload = function(e) {
                        try {
                            const presetData = JSON.parse(e.target.result);
                            
                            // Show dialog to enter preset name
                            Swal.fire({
                                title: 'Import Preset',
                                input: 'text',
                                inputLabel: 'Enter name for the preset',
                                inputPlaceholder: 'Preset name',
                                showCancelButton: true,
                                allowOutsideClick: false,
                                allowEscapeKey: false,
                                inputValidator: (value) => {
                                    if (!value) return 'You need to enter a name!';
                                    if (value === 'wp-core') return 'Cannot use reserved name "wp-core"';
                                }
                            }).then((result) => {
                                if (result.isConfirmed) {
                                    const name = result.value;
                                    const data = JSON.stringify(presetData);
                                    
                                    // Save the imported preset
                                    $.post('?save_preset=1', { name, data }, function(resp) {
                                        if (resp.success) {
                                            // First refresh the presets dropdown
                                            $.get('?list_presets=1', function(data) {
                                                let $presetSelect = $('#presetSelect');
                                                $presetSelect.empty();
                                                $presetSelect.append('<option value="">-- Select a preset --</option>');
                                                $presetSelect.append('<option value="wp-core">WordPress core files</option>');
                                                
                                                let presets = data.presets || [];
                                                presets.forEach(function(presetName) {
                                                    if (presetName !== 'wp-core') {
                                                        $presetSelect.append(`<option value="${presetName}">${presetName}</option>`);
                                                    }
                                                });
                                                
                                                // Now select the imported preset and trigger change
                                                $presetSelect.val(name).trigger('change');
                                                showNotification('Preset imported and loaded successfully', 'success');
                                            });
                                        } else {
                                            showNotification('Failed to import preset', 'error');
                                        }
                                    });
                                }
                            });
                        } catch (e) {
                            showNotification('Invalid preset file format', 'error');
                        }
                    };
                    reader.readAsText(file);
                };

                fileInput.click();
                // Clean up
                document.body.removeChild(fileInput);
            });

            // --- FOLDER/FILE LIST UI ---
            function updateFolderList() {
                const folderList = $('#folderList');
                folderList.empty();
                folders.forEach((folder, index) => {
                    folderList.append(`
                        <div class="folder-item">
                            <span><i class="fas fa-folder"></i> ${folder}</span>
                            <button class="remove-btn" onclick="removeFolder(${index})">
                                <i class="fa-solid fa-trash"></i>
                            </button>
                        </div>
                    `);
                });
            }
            function updateFileList() {
                const fileList = $('#fileList');
                fileList.empty();
                files.forEach((file, index) => {
                    fileList.append(`
                        <div class="file-item">
                            <span><i class="fas fa-file"></i> ${file}</span>
                            <button class="remove-btn" onclick="removeFile(${index})">
                                <i class="fa-solid fa-trash"></i>
                            </button>
                        </div>
                    `);
                });
            }
            window.addFolder = function() {
                let folderPath = normalizePathSlashes($('#folderPath').val().trim());
                if (folderPath && !folders.includes(folderPath)) {
                    folders.push(folderPath);
                    updateFolderList();
                    $('#folderPath').val('');
                    showNotification('Folder added successfully!', 'success');
                } else if (folders.includes(folderPath)) {
                    showNotification('Folder already added', 'error');
                } else {
                    showNotification('Please enter a folder path', 'error');
                }
            };
            window.addFile = function() {
                let filePath = normalizePathSlashes($('#filePath').val().trim());
                if (filePath && !files.includes(filePath)) {
                    files.push(filePath);
                    updateFileList();
                    $('#filePath').val('');
                    showNotification('File added successfully!', 'success');
                } else if (files.includes(filePath)) {
                    showNotification('File already added', 'error');
                }
                else {
                    showNotification('Please enter a file path', 'error');
                }
            };
            window.removeFolder = function(index) {
                folders.splice(index, 1);
                updateFolderList();
                updateDeleteSectionVisibility();
                showNotification('Folder removed', 'info');
            };
            window.removeFile = function(index) {
                files.splice(index, 1);
                updateFileList();
                updateDeleteSectionVisibility();
                showNotification('File removed', 'info');
            };

            window.addSelectedFolders = function(paths) {
                let newPaths = [];
                paths.forEach(path => {
                    const p = normalizePathSlashes(path);
                    if (!folders.includes(p)) {
                        newPaths.push(p);
                    }
                });

                if (newPaths.length === 0 && paths.length > 0) {
                    showNotification('All selected folders are already in the list.', 'error');
                    return;
                }

                if (newPaths.length > 0) {
                    folders.push(...newPaths);
                    updateFolderList();
                    updateDeleteSectionVisibility();
                    showNotification(`${newPaths.length} folder(s) added.`, 'success');
                    if (paths.length > newPaths.length) {
                        showNotification(`${paths.length - newPaths.length} folder(s) were already selected.`, 'info');
                    }
                    Swal.close();
                }
            }

            window.addSelectedFiles = function(paths) {
                let newPaths = [];
                paths.forEach(path => {
                    const p = normalizePathSlashes(path);
                    if (!files.includes(p)) {
                        newPaths.push(p);
                    }
                });

                if (newPaths.length === 0 && paths.length > 0) {
                    showNotification('All selected files are already in the list.', 'error');
                    return;
                }

                if (newPaths.length > 0) {
                    files.push(...newPaths);
                    updateFileList();
                    updateDeleteSectionVisibility();
                    showNotification(`${newPaths.length} file(s) added.`, 'success');
                    if (paths.length > newPaths.length) {
                        showNotification(`${paths.length - newPaths.length} file(s) were already selected.`, 'info');
                    }
                    Swal.close();
                }
            }

            // --- DELETE ACTION ---
            function executeDelete() {
                if (folders.length === 0 && files.length === 0) {
                    showNotification('No folders or files to delete', 'error');
                    return;
                }

                function startDeletionProcess(backupName = null) {
                    $.post('?start_deletion=1', {
                        folders: folders,
                        files: files,
                        softdelete: options.softDelete ? 1 : 0,
                        backup: options.backup ? 1 : 0,
                        dryrun: options.dryRun ? 1 : 0,
                        backupName: backupName
                    }, function(startResp) {
                        if (startResp.error) {
                            showNotification(startResp.error, 'error');
                            return;
                        }
                        if (!startResp.sessionId) {
                            showNotification('Failed to start delete session', 'error');
                            return;
                        }
                        let sessionId = startResp.sessionId;
                        let total = startResp.total;
                        let processed = 0;
                        let allResults = {};

                        function processBatch() {
                            $.post('?process_deletion=1', { sessionId: sessionId }, function(procResp) {
                                // Server was busy with an overlapping round-trip; back off and retry.
                                if (procResp && procResp.busy) { setTimeout(processBatch, 300); return; }
                                processed += Object.keys(procResp.results || {}).length;
                                Object.assign(allResults, procResp.results);

                                if (procResp.finished) {
                                    let finalMessage = options.dryRun ? 'Dry run finished.' : 'Deletion completed!';
                                    showNotification(finalMessage, 'success');
                                    
                                    if (options.dryRun) {
                                        let resultsHtml = '<ul style="text-align:left; max-height: 200px; overflow-y: auto;">';
                                        for (const path in allResults) {
                                            resultsHtml += `<li><strong>${path}:</strong> ${allResults[path]}</li>`;
                                        }
                                        resultsHtml += '</ul>';
                                        Swal.fire({
                                            title: 'Dry Run Results',
                                            html: resultsHtml,
                                            icon: 'info'
                                        });
                                    } else {
                                        Swal.close();
                                    }

                                    folders = [];
                                    files = [];
                                    updateFolderList();
                                    updateFileList();
                                    $('#deleteForm')[0].reset();
                                    
                                    if (!options.dryRun) {
                                        renderTrash();
                                        renderBackups();
                                    }

                                } else {
                                    let progressTitle = options.dryRun ? 'Simulating Deletion' : 'Deleting Files';
                                    Swal.update({
                                        title: progressTitle,
                                        html: `<div>Processed ${processed} of ${total}...</div>`,
                                        showConfirmButton: false,
                                        allowOutsideClick: false,
                                        allowEscapeKey: false
                                    });
                                    setTimeout(processBatch, 200);
                                }
                            }).fail(function() {
                                showNotification('Error during batch processing', 'error');
                            });
                        }

                        let initialTitle = options.dryRun ? 'Simulating Deletion' : 'Deleting Files';
                        Swal.fire({
                            title: initialTitle,
                            html: `<div>Processed 0 of ${total}...</div>`,
                            showConfirmButton: false,
                            allowOutsideClick: false,
                            allowEscapeKey: false,
                            didOpen: () => {
                                Swal.showLoading();
                            }
                        });

                        processBatch();
                    });
                }

                // Build folder/file lists with icons
                function buildList(items, iconClass) {
                    if (!items.length) return '<li>None</li>';
                    return items.map(item => `<li><i class='${iconClass}'></i> ${item}</li>`).join('');
                }
                let folderListHtml = `<ul>${buildList(folders, 'fas fa-folder')}</ul>`;
                let fileListHtml = `<ul>${buildList(files, 'fas fa-file')}</ul>`;

                let doubleConfirm = (folders.length > 1 || files.length > 1);
                let doubleConfirmHtml = doubleConfirm ? `
                    <div id='doubleConfirmArea' style='margin-top:12px;'>
                        <div style='margin-bottom:0.5rem;color:#b00;font-weight:bold;'>Type <span style='background:#eee;padding:2px 6px;border-radius:4px;'>DELETE ALL</span> to confirm mass deletion:</div>
                        <input type='text' id='doubleConfirmInput' style='padding:8px 12px;font-size:1.08rem;border:1.5px solid #d0d7de;border-radius:6px;width:180px;'>
                        <div id='doubleConfirmError' style='color:#b00;font-size:0.98em;margin-top:4px;display:none;'>You must type DELETE ALL to proceed.</div>
                    </div>
                ` : '';

                Swal.fire({
                    title: 'Confirm Deletion',
                    html: `
                        <div style='text-align:left;max-height:200px;overflow-y:auto;'>
                            <b>Folders:</b> ${folderListHtml}
                            <b>Files:</b> ${fileListHtml}
                            <b>Backup:</b> ${options.backup ? 'Yes' : 'No'}<br>
                            <b>Dry Run:</b> ${options.dryRun ? 'Yes' : 'No'}<br>
                            <b>Soft Delete:</b> ${options.softDelete ? 'Yes' : 'No'}
                        </div>
                        <div>${doubleConfirmHtml}</div>
                    `,
                    icon: 'warning',
                    showCancelButton: true,
                    confirmButtonText: '<i class="fas fa-trash-alt"></i> Delete',
                    cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                    confirmButtonColor: '#dc3545',
                    allowOutsideClick: false,
                    allowEscapeKey: false,
                    didOpen: () => {
                        if (doubleConfirm) {
                            const $input = $('#doubleConfirmInput');
                            const $error = $('#doubleConfirmError');
                            Swal.getConfirmButton().disabled = true;
                            $input.on('input', function() {
                                if ($input.val().trim() === 'DELETE ALL') {
                                    Swal.getConfirmButton().disabled = false;
                                    $error.hide();
                                } else {
                                    Swal.getConfirmButton().disabled = true;
                                    if ($input.val().length > 0) $error.show();
                                    else $error.hide();
                                }
                            });
                        }
                    }
                }).then((result) => {
                    if (result.isConfirmed) {
                        if (options.backup && !options.dryRun) {
                            Swal.fire({
                                title: 'Enter Backup Name',
                                input: 'text',
                                inputValue: `backup_${new Date().toISOString().slice(0, 19).replace('T', '_').replace(/:/g, '-')}`,
                                showCancelButton: true,
                                cancelButtonColor: '#ff6b6b',
                                confirmButtonColor: '#667eea',
                                confirmButtonText: 'Create Backup & Proceed',
                                inputValidator: (value) => {
                                    if (!value) {
                                        return 'Please enter a name for the backup.';
                                    }
                                }
                            }).then((backupResult) => {
                                if (backupResult.isConfirmed) {
                                    startDeletionProcess(backupResult.value);
                                }
                            });
                        } else {
                            startDeletionProcess();
                        }
                    }
                });
            }

            // Toggle advanced options dropdown
            window.toggleAdvancedOptions = function() {
                $('#advancedDropdown').toggleClass('show');
            };

            // Show about modal
            window.showAbout = function() {
                $('#advancedDropdown').removeClass('show');
                
                Swal.fire({
                    title: '<i class="fas fa-info-circle"></i> About WordPress Tools Kit',
                    html: `
                        <div style="text-align: left;">
                            <p><strong>Author:</strong> Tawhidul Islam</p>
                            <p><strong>Version:</strong> 2.0.0</p>
                            <p><strong>Description:</strong> Advanced WordPress cleanup and management tool</p>
                            <p><strong>Features:</strong></p>
                            <ul>
                                <li><i class="fa-solid fa-circle-check"></i> Preset management</li>
                                <li><i class="fa-solid fa-circle-check"></i> Safe deletion with backup options</li>
                                <li><i class="fa-solid fa-circle-check"></i> Dry run mode for testing</li>
                                <li><i class="fa-solid fa-circle-check"></i> Bulk file and folder operations</li>
                            </ul>
                        </div>
                    `,
                    confirmButtonText: '<i class="fas fa-times"></i> Close',
                    confirmButtonColor: '#ff6b6b',
                    customClass: {
                        confirmButton: 'btn btn-primary'
                    }
                });
            };

            // --- WORDPRESS SALTS UPDATE ---
            window.updateWordPressSalts = function() {
                Swal.fire({
                    title: '<i class="fas fa-key"></i> Update WordPress Salts',
                    html: `
                        <div style="text-align: left;">
                            <p><strong>What this does:</strong></p>
                            <ul>
                                <li><i class="fas fa-shield-alt"></i> Fetches new security salts from WordPress.org API</li>
                                <li><i class="fas fa-backup"></i> Creates a backup of wp-config.php before updating</li>
                                <li><i class="fas fa-sync"></i> Updates all authentication keys and salts</li>
                                <li><i class="fas fa-user-lock"></i> Forces all users to log in again (security measure)</li>
                            </ul>
                            <p><strong>Warning:</strong> This will invalidate all existing user sessions!</p>
                        </div>
                    `,
                    icon: 'warning',
                    showCancelButton: true,
                    confirmButtonText: '<i class="fas fa-key"></i> Update Salts',
                    cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                    confirmButtonColor: '#dc3545',
                    cancelButtonColor: '#6c757d',
                    allowOutsideClick: false,
                    allowEscapeKey: false,
                }).then((result) => {
                    if (result.isConfirmed) {
                        // Show loading state
                        Swal.fire({
                            title: 'Updating WordPress Salts',
                            html: `
                                <div class="text-center">
                                    <div class="spinner-border text-primary mb-3" role="status">
                                        <span class="visually-hidden">Loading...</span>
                                    </div>
                                    <p>Fetching new salts from WordPress.org...</p>
                                    <p class="text-muted">Please wait, this may take a moment...</p>
                                </div>
                            `,
                            allowOutsideClick: false,
                            allowEscapeKey: false,
                            showConfirmButton: false,
                            didOpen: () => {
                                Swal.showLoading();
                            }
                        });
                        
                        // Make the API call
                        $.post('?update_wp_salts=1', function(response) {
                            Swal.close();
                            
                            if (response.message) {
                                Swal.fire({
                                    title: '<i class="fas fa-check-circle"></i> Salts Updated Successfully!',
                                    html: `
                                        <div style="text-align: left;">
                                            <p><strong>✅ WordPress salts have been updated!</strong></p>
                                            <p><strong>Backup created:</strong> ${response.backup_path}</p>
                                            <p><strong>Salts updated:</strong> ${response.salts_updated.join(', ')}</p>
                                            ${response.salt_file_created ? `<p><strong>Salt file created:</strong> ${response.salt_file_path}</p>` : ''}
                                            <hr>
                                            <p><strong>Important:</strong></p>
                                            <ul>
                                                <li>All user sessions have been invalidated</li>
                                                <li>Users will need to log in again</li>
                                                <li>Keep the backup file for safety</li>
                                                ${response.salt_file_created ? '<li>wp-salt.php file has been created/updated</li>' : ''}
                                            </ul>
                                        </div>
                                    `,
                                    icon: 'success',
                                    confirmButtonText: '<i class="fas fa-times"></i> Close',
                                    confirmButtonColor: '#ff6b6b',
                                });
                                showNotification('WordPress salts updated successfully!', 'success');
                            } else {
                                Swal.fire({
                                    title: '<i class="fas fa-exclamation-triangle"></i> Update Failed',
                                    html: `<p>${response.error || 'Unknown error occurred'}</p>`,
                                    icon: 'error',
                                    confirmButtonText: '<i class="fas fa-times"></i> Close',
                                    confirmButtonColor: '#dc3545'
                                });
                                showNotification('Failed to update WordPress salts', 'error');
                            }
                        }).fail(function(xhr) {
                            Swal.close();
                            let errorMsg = 'Network error occurred';
                            try {
                                const response = JSON.parse(xhr.responseText);
                                errorMsg = response.error || errorMsg;
                            } catch (e) {
                                // Use default error message
                            }
                            
                            Swal.fire({
                                title: '<i class="fas fa-exclamation-triangle"></i> Update Failed',
                                html: `<p>${errorMsg}</p>`,
                                icon: 'error',
                                confirmButtonText: '<i class="fas fa-times"></i> Close',
                                confirmButtonColor: '#dc3545'
                            });
                            showNotification('Failed to update WordPress salts', 'error');
                        });
                    }
                });
            };

            // --- ONE CLICK FIX FUNCTION ---
            window.oneClickFix = function() {
                Swal.fire({
                    title: '<i class="fa-solid fa-hammer"></i> One Click Fix',
                    html: `
                        <div style="text-align: left; margin: 20px 0;">
                            <p><strong>This will perform the following actions in sequence:</strong></p>
                            <ol style="margin: 15px 0; padding-left: 20px;">
                                <li><i class="fas fa-download"></i> Download/Update WordPress Core Files</li>
                                <li><i class="fas fa-key"></i> Update WordPress Authentication Salts</li>
                                <li><i class="fas fa-plug"></i> Check and Update WordPress.org Plugins</li>
                                <li><i class="fas fa-shield-alt"></i> Fix File Permissions</li>
                            </ol>
                            <p style="color: #dc3545; font-size: 14px;">
                                <i class="fas fa-exclamation-triangle"></i> 
                                <strong>Warning:</strong> This will force all users to log in again.
                            </p>
                        </div>
                    `,
                    icon: 'warning',
                    showCancelButton: true,
                    confirmButtonText: '<i class="fas fa-play"></i> Start Fix',
                    cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                    confirmButtonColor: '#28a745',
                    cancelButtonColor: '#ff6b6b',
                    reverseButtons: true
                }).then((result) => {
                    if (result.isConfirmed) {
                        startOneClickFix();
                    }
                });
            };

            function startOneClickFix() {
                let currentStep = 0;
                const totalSteps = 4;
                const steps = [
                    { name: 'Downloading WordPress Core', action: downloadWordPress },
                    { name: 'Updating WordPress Salts', action: updateWordPressSaltsPromise },
                    { name: 'Updating WordPress Plugins', action: checkWordPressPlugins },
                    { name: 'Fixing File Permissions', action: fixFilePermissions }
                ];

                function executeStep() {                    
                    if (currentStep >= totalSteps) {
                        // All steps completed
                        Swal.fire({
                            title: '<i class="fas fa-check-circle"></i> One Click Fix Complete!',
                            html: `
                                <div style="text-align: center;">
                                    <p><strong>All fixes have been applied successfully!</strong></p>
                                    <p style="margin-top: 15px; color: #6c757d;">
                                        Your WordPress installation has been updated and secured.
                                    </p>
                                </div>
                            `,
                            icon: 'success',
                            confirmButtonText: '<i class="fas fa-times"></i> Close',
                            confirmButtonColor: '#28a745'
                        });
                        showNotification('One Click Fix completed successfully!', 'success');
                        return;
                    }

                    const step = steps[currentStep];
                    
                    Swal.fire({
                        title: `<i class="fas fa-spinner fa-spin"></i> ${step.name}`,
                        html: `
                            <div style="text-align: center;">
                                <p>Step ${currentStep + 1} of ${totalSteps}</p>
                                <div style="margin: 20px 0;">
                                    <div style="width: 100%; background-color: #e9ecef; border-radius: 10px; height: 8px;">
                                        <div style="width: ${((currentStep + 1) / totalSteps) * 100}%; background-color: #28a745; height: 8px; border-radius: 10px; transition: width 0.3s;"></div>
                                    </div>
                                </div>
                            </div>
                        `,
                        allowOutsideClick: false,
                        allowEscapeKey: false,
                        showConfirmButton: false,
                        didOpen: () => {
                            Swal.showLoading();
                        }
                    });

                    // Execute the current step
                    try {
                        const stepPromise = step.action();
                        if (stepPromise && typeof stepPromise.then === 'function') {
                            stepPromise.then(() => {
                                currentStep++;
                                executeStep();
                            }).catch((error) => {
                                Swal.fire({
                                    title: '<i class="fas fa-exclamation-triangle"></i> Error',
                                    text: `Failed at step: ${step.name}. ${error}`,
                                    icon: 'error',
                                    confirmButtonText: '<i class="fas fa-times"></i> Close',
                                    confirmButtonColor: '#ff6b6b'
                                });
                                showNotification(`One Click Fix failed at: ${step.name}`, 'error');
                            });
                        } else {
                            throw new Error(`Step action did not return a Promise`);
                        }
                    } catch (error) {
                        Swal.fire({
                            title: '<i class="fas fa-exclamation-triangle"></i> Error',
                            text: `Failed at step: ${step.name}. ${error.message}`,
                            icon: 'error',
                            confirmButtonText: '<i class="fas fa-times"></i> Close',
                            confirmButtonColor: '#ff6b6b'
                        });
                        showNotification(`One Click Fix failed at: ${step.name}`, 'error');
                    }
                }

                executeStep();
            }

            // Helper functions for each step
            function updateWordPressSaltsPromise() {
                return new Promise((resolve, reject) => {
                    // Direct AJAX call without confirmation dialog
                    $.ajax({
                        url: '?update_wp_salts=1',
                        method: 'POST',
                        data: {},
                        dataType: 'json',
                        success: function(response) {
                            if (response && response.message) {
                                resolve();
                            } else {
                                const errorMsg = response.error || 'Failed to update WordPress salts';
                                console.log('Update WordPress Salts rejected:', errorMsg);
                                reject(errorMsg);
                            }
                        },
                        error: function(xhr, status, error) {
                            console.log('Update WordPress Salts error:', xhr, status, error);
                            let errorMsg = 'Failed to update WordPress salts';
                            if (xhr.responseText) {
                                try {
                                    const response = JSON.parse(xhr.responseText);
                                    errorMsg = response.error || response.message || errorMsg;
                                } catch (e) {
                                    errorMsg = xhr.responseText || errorMsg;
                                }
                            }
                            console.log('Update WordPress Salts final error:', errorMsg);
                            reject(errorMsg);
                        }
                    });
                });
            }

            function downloadWordPress() {
                return new Promise((resolve, reject) => {
                    $.ajax({
                        url: '?download_wp=1',
                        method: 'POST',
                        data: {},
                        dataType: 'json',
                        timeout: 300000, // 5-minute timeout
                        success: function(response) {
                            if (response && response.success) {
                                resolve();
                            } else {
                                const errorMsg = response.message || response.error || 'Failed to download WordPress';
                                console.log('Download WordPress rejected:', errorMsg);
                                reject(errorMsg);
                            }
                        },
                        error: function(xhr, status, error) {
                            console.log('Download WordPress error:', xhr, status, error);
                            let errorMsg = 'Failed to download WordPress';
                            if (status === 'timeout') {
                                errorMsg = 'Download timed out. The server took too long to respond.';
                            } else if (xhr.responseText) {
                                try {
                                    const response = JSON.parse(xhr.responseText);
                                    errorMsg = response.error || response.message || errorMsg;
                                } catch (e) {
                                    errorMsg = xhr.responseText || errorMsg;
                                }
                            }
                            console.log('Download WordPress final error:', errorMsg);
                            reject(errorMsg);
                        }
                    });
                });
            }

            function checkWordPressPlugins() {
                return new Promise((resolve, reject) => {
                    $.ajax({
                        url: '?list_plugins=1',
                        method: 'GET',
                        dataType: 'json',
                        success: function(response) {
                            if (response && response.plugins && response.plugins.length >= 0) {
                                resolve();
                            } else {
                                const errorMsg = response.error || 'Failed to check plugins';
                                console.log('Check plugins rejected:', errorMsg);
                                reject(errorMsg);
                            }
                        },
                        error: function(xhr, status, error) {
                            console.log('Check plugins error:', xhr, status, error);
                            let errorMsg = 'Failed to check plugins';
                            if (xhr.responseText) {
                                try {
                                    const response = JSON.parse(xhr.responseText);
                                    errorMsg = response.error || response.message || errorMsg;
                                } catch (e) {
                                    errorMsg = xhr.responseText || errorMsg;
                                }
                            }
                            console.log('Check plugins final error:', errorMsg);
                            reject(errorMsg);
                        }
                    });
                });
            }

            function fixFilePermissions() {
                return new Promise((resolve, reject) => {
                    $.ajax({
                        url: '?fix_wp_permissions=1',
                        method: 'POST',
                        data: {},
                        dataType: 'json',
                        success: function(response) {
                            if (response && response.message) {
                                resolve();
                            } else {
                                const errorMsg = response.error || 'Failed to fix permissions';
                                console.log('Fix permissions rejected:', errorMsg);
                                reject(errorMsg);
                            }
                        },
                        error: function(xhr, status, error) {
                            console.log('Fix permissions error:', xhr, status, error);
                            let errorMsg = 'Failed to fix permissions';
                            if (xhr.responseText) {
                                try {
                                    const response = JSON.parse(xhr.responseText);
                                    errorMsg = response.error || response.message || errorMsg;
                                } catch (e) {
                                    errorMsg = xhr.responseText || errorMsg;
                                }
                            }
                            console.log('Fix permissions final error:', errorMsg);
                            reject(errorMsg);
                        }
                    });
                });
            }

            // --- ADVANCED OPTIONS ---
            window.showOptionsModal = function() {
                $('#advancedDropdown').removeClass('show');
                Swal.fire({
                    title: '<i class="fas fa-sliders-h"></i> Advanced Options',
                    html: `
                        <div class="options-modal">
                            <div class="checkbox-group">
                                <div class="checkbox-item">
                                    <input type="checkbox" id="modalBackup" ${options.backup ? 'checked' : ''}>
                                    <label for="modalBackup">
                                        <i class="fas fa-shield-alt"></i> Backup before delete
                                    </label>
                                </div>
                                <div class="checkbox-item">
                                    <input type="checkbox" id="modalDryRun" ${options.dryRun ? 'checked' : ''}>
                                    <label for="modalDryRun">
                                        <i class="fas fa-play-circle"></i> Dry Run (pretend, do not delete)
                                    </label>
                                </div>
                                <div class="checkbox-item">
                                    <input type="checkbox" id="modalSoftDelete" ${options.softDelete ? 'checked' : ''}>
                                    <label for="modalSoftDelete">
                                        <i class="fas fa-trash-restore"></i> Soft Delete
                                    </label>
                                </div>
                            </div>
                        </div>
                    `,
                    showCancelButton: true,
                    confirmButtonText: '<i class="fas fa-save"></i> Save Options',
                    cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                    cancelButtonColor: '#ff6b6b',
                    confirmButtonColor: '#008000',
                    allowOutsideClick: false,
                    allowEscapeKey: false,
                    customClass: {
                        confirmButton: 'btn btn-primary',
                        cancelButton: 'btn btn-light'
                    },
                    preConfirm: () => {
                        const backup = $('#modalBackup').is(':checked');
                        const dryRun = $('#modalDryRun').is(':checked');
                        const softDelete = $('#modalSoftDelete').is(':checked');

                        if (!isValidOptionCombo(backup, dryRun, softDelete)) {
                            showNotification('Any single option, or Backup + Soft Delete.', 'error');
                            return false; // Prevent closing
                        }

                        options.backup = backup;
                        options.dryRun = dryRun;
                        options.softDelete = softDelete;
                        syncInlineOptionsUI(); // keep the inline panel in sync
                        return options;
                    }
                }).then((result) => {
                    if (result.isConfirmed) {
                        showNotification('Options saved successfully!', 'success');
                    }
                });
            };

            // --- FOLDER/FILE BROWSER ---
            window.browseFolders = function() {
                openBrowserModal('folder');
            };
            window.browseFiles = function() {
                openBrowserModal('file');
            };
            function openBrowserModal(type) {
                let currentDir = '';

                function bindBrowserEvents() {
                    // Re-bind events for the control buttons
                    $('#backToRootBrowser').off('click').on('click', function() {
                        loadDir(''); // Go back to root directory
                    });
                    
                    $('#selectAllInBrowser').off('click').on('click', function() {
                        $('.browser-checkbox').prop('checked', true);
                    });
                    
                    $('#deselectAllInBrowser').off('click').on('click', function() {
                        $('.browser-checkbox').prop('checked', false);
                    });
                    
                    $('#addSelectedItems').off('click').on('click', function() {
                        const selectedPaths = [];
                        $('.browser-checkbox:checked').each(function() {
                            selectedPaths.push($(this).data('path'));
                        });

                        if (selectedPaths.length === 0) {
                            showNotification('Please select at least one item.', 'error');
                            return;
                        }

                        if (type === 'folder') {
                            addSelectedFolders(selectedPaths);
                        } else {
                            addSelectedFiles(selectedPaths);
                        }
                    });

                    // Search functionality
                    $('#browserSearchBtn').off('click').on('click', function() {
                        const searchTerm = $('#browserSearchInput').val().trim();
                        
                        // If no search term, just reload current directory
                        if (!searchTerm) {
                            loadDir(currentDir);
                            return;
                        }
                        
                        // Show loading
                        $('#browserResults').html('<div class="text-center"><i class="fas fa-spinner fa-spin"></i> Searching...</div>');
                        
                        const params = {
                            type: 'name',
                            pattern: searchTerm,
                            directory: '', // Always search from root directory
                            recursive: '1'
                        };
                        
                        $.get('?search_files=1', params, function(response) {
                            
                                                            if (response.results && response.results.length > 0) {
                                    let filteredResults = response.results;
                
                                
                                // Display search results
                                let searchResultsHtml = '';
                                const folders = filteredResults.filter(item => item.type === 'folder');
                                const files = filteredResults.filter(item => item.type === 'file');
                                
                                
                                
                                // Filter based on modal type
                                let itemsToShow = [];
                                if (type === 'folder') {
                                    // Only show folders
                                    itemsToShow = folders;
                
                                } else if (type === 'file') {
                                    // Only show files
                                    itemsToShow = files;
                
                                } else {
                                    // Show both (default behavior)
                                    itemsToShow = [...folders, ...files];
                
                                }
                                
                                // Show items
                                itemsToShow.forEach(function(item) {
                                    const itemId = `${item.type === 'folder' ? 'folder' : 'file'}_${btoa(item.path).replace(/[^a-z0-9]/gi, '')}`;
                                    const icon = item.type === 'folder' ? '📁' : '📄';
                                    const isFolder = item.type === 'folder';
                                    
                                    searchResultsHtml += `
                                        <div class='browser-item'>
                                            <input type='checkbox' id='${itemId}' class='browser-checkbox' data-path='${normalizePathSlashes(item.path)}'>
                                            <label for='${itemId}'>
                                                ${isFolder ? `<a href='#' class='browserDir' data-path='${normalizePathSlashes(item.path)}'>${icon} ${item.name}</a>` : `${icon} ${item.name}`}
                                                <small class="text-muted">${item.path}</small>
                                            </label>
                                        </div>`;
                                });
                                
                                if (searchResultsHtml) {
                                    $('#browserResults').html(searchResultsHtml);
                                    bindBrowserEvents(); // Re-bind events for new elements
                                } else {
                                    $('#browserResults').html('<div class="text-center">No items found matching your criteria.</div>');
                                }
                            } else {
                                $('#browserResults').html('<div class="text-center">No items found matching your criteria.</div>');
                            }
                        }).fail(function() {
                            $('#browserResults').html('<div class="text-center text-danger">Search failed. Please try again.</div>');
                        });
                    });

                    // Re-bind events for file/directory navigation
                    $('.browserDir').off('click').on('click', function(e) {
                        e.preventDefault();
                        loadDir($(this).data('path'));
                    });
                    $('.browserUp').off('click').on('click', function(e) {
                        e.preventDefault();
                        let up = currentDir.split('/').slice(0, -1).join('/');
                        loadDir(up);
                    });
                    // Breadcrumb navigation
                    $('.breadcrumb-link').off('click').on('click', function(e) {
                        e.preventDefault();
                        loadDir($(this).data('dir'));
                    });
                    $('.browserFile').off('click').on('click', function(e) {
                        e.preventDefault();
                        let path = $(this).data('path');
                        $('#filePath').val(normalizePathSlashes(path));
                        Swal.close();
                    });
                    if (type === 'folder') {
                        $('.browserDir').off('dblclick').on('dblclick', function(e) {
                            e.preventDefault();
                            let path = $(this).data('path');
                            $('#folderPath').val(normalizePathSlashes(path));
                            Swal.close();
                        });
                    }
                }

                function loadDir(dir) {
                    $.get('?listdir=1&dir=' + encodeURIComponent(dir), function(resp) {
                        currentDir = dir;
                        
                        // Generate breadcrumb navigation
                        let breadcrumbHtml = '<div class="breadcrumb-container mb-3" style="background: #f8f9fa; padding: 10px; border-radius: 6px; border: 1px solid #e9ecef;font-size:12px;">';
                        breadcrumbHtml += '<span style="font-weight: bold; color: #495057;">Path: </span>';
                        
                        if (!dir || dir === '') {
                            breadcrumbHtml += '<a href="#" class="breadcrumb-link" data-dir="" style="color: #0073e6; text-decoration: none; font-weight: bold;">🏠 Root</a>';
                        } else {
                            const pathParts = dir.split('/').filter(part => part !== '');
                            breadcrumbHtml += '<a href="#" class="breadcrumb-link" data-dir="" style="color: #0073e6; text-decoration: none; font-weight: bold;">🏠 Root</a>';
                            
                            let currentPath = '';
                            for (let i = 0; i < pathParts.length; i++) {
                                currentPath += (currentPath ? '/' : '') + pathParts[i];
                                const isLast = i === pathParts.length - 1;
                                const linkStyle = isLast ? 'color: #495057; text-decoration: none; font-weight: bold;' : 'color: #0073e6; text-decoration: none;';
                                const separator = i < pathParts.length - 1 ? ' <span style="color: #6c757d; margin: 0 5px;">/</span> ' : '';
                                
                                if (isLast) {
                                    breadcrumbHtml += separator + '<span style="color: #6c757d; margin: 0 5px;">/</span> <span style="' + linkStyle + '">📁 ' + escapeHtml(pathParts[i]) + '</span>';
                                } else {
                                    breadcrumbHtml += separator + '<a href="#" class="breadcrumb-link" data-dir="' + escapeHtml(currentPath) + '" style="' + linkStyle + '">📁 ' + escapeHtml(pathParts[i]) + '</a>';
                                }
                            }
                        }
                        breadcrumbHtml += '</div>';
                        
                        let fileListHtml = '';
                        if (dir) {
                            fileListHtml += `<div class='browser-item'><a href='#' class='browserUp'>.. <i class="fa-solid fa-turn-up"></i> (Up)</a></div>`;
                        }
                        let folders = resp.items.filter(i => i.type === 'folder').sort((a, b) => a.name.localeCompare(b.name));
                        let files = resp.items.filter(i => i.type === 'file').sort((a, b) => a.name.localeCompare(b.name));
                        
                        if (type === 'folder') {
                            folders.forEach(function(item) {
                                const itemId = `folder_${btoa(item.path).replace(/[^a-z0-9]/gi, '')}`;
                                fileListHtml += `
                                    <div class='browser-item'>
                                        <input type='checkbox' id='${itemId}' class='browser-checkbox' data-path='${normalizePathSlashes(item.path)}'>
                                        <label for='${itemId}'><a href='#' class='browserDir' data-path='${normalizePathSlashes(item.path)}'>📁 ${item.name}</a></label>
                                    </div>`;
                            });
                        } else { // type === 'file'
                            folders.forEach(function(item) {
                                fileListHtml += `
                                    <div class='browser-item'>
                                        <a href='#' class='browserDir' data-path='${normalizePathSlashes(item.path)}' style='padding-left: 5px; text-decoration: none; color: inherit; display: block;'>
                                            📁 ${item.name}
                                        </a>
                                    </div>`;
                            });
                            files.forEach(function(item) {
                                const itemId = `file_${btoa(item.path).replace(/[^a-z0-9]/gi, '')}`;
                                fileListHtml += `
                                    <div class='browser-item'>
                                        <input type='checkbox' id='${itemId}' class='browser-checkbox' data-path='${normalizePathSlashes(item.path)}'>
                                        <label for='${itemId}'>📄 ${item.name}</label>
                                    </div>`;
                            });
                        }

                        const modalHtml = `
                            <div class="browser-search-section mb-3">
                                <div class="row">
                                    <div class="col-md-9">
                                        <input type="text" id="browserSearchInput" class="form-control form-control-md" placeholder="${type === 'folder' ? 'Search folders...' : type === 'file' ? 'Search files...' : 'Search files and folders...'}">
                                    </div>
                                    <div class="col-md-3">
                                        <button id="browserSearchBtn" class="btn btn-primary btn-md w-100">
                                            <i class="fas fa-search"></i> Search
                                        </button>
                                    </div>
                                </div>
                            </div>
                            ${breadcrumbHtml}
                            <div class="text-right mb-3">
                                <button id="backToRootBrowser" class="btn btn-info btn-md me-2">
                                    <i class="fa-solid fa-home"></i> Root
                                </button>
                                <button id="selectAllInBrowser" class="btn btn-secondary btn-md me-2">
                                    <i class="fas fa-check-square"></i> Select All
                                </button>
                                <button id="deselectAllInBrowser" class="btn btn-secondary btn-md me-2">
                                    <i class="fas fa-square"></i> Deselect All
                                </button>
                                <button id="addSelectedItems" class="btn btn-primary btn-md">
                                    <i class="fas fa-plus"></i> Add Selected
                                </button>
                            </div>
                            <div id="browserResults" style='max-height:300px;overflow:auto;'>${fileListHtml}</div>
                        `;
                        
                        if (Swal.isVisible()) {
                            Swal.update({ html: modalHtml });
                            bindBrowserEvents();
                        } else {
                            Swal.fire({
                                title: type === 'folder' ? 'Browse Folders' : type === 'file' ? 'Browse Files' : 'Browse',
                                html: modalHtml,
                                showCancelButton: true,
                                cancelButtonText: '<i class="fas fa-times"></i> Close',
                                customClass: {
                                    header: 'swal2-header-with-root-button',
                                    cancelButton: 'btn btn-lg btn-secondary'
                                },
                                cancelButtonColor: '#ff6b6b',
                                showConfirmButton: false,
                                allowOutsideClick: false,
                                allowEscapeKey: false,
                                didOpen: () => {
                                    bindBrowserEvents();
                                }
                            });
                        }
                    });
                }
                loadDir(currentDir);
            }

            // --- ZIP BROWSER FUNCTIONALITY ---
            let zipSelectedItems = new Set();
            let currentZipDir = '';

            function updateZipSelectedCount() {
                $('#zipSelectedCount').text(zipSelectedItems.size);
                updateSelectedItemsDisplay();
            }

            function updateSelectedItemsDisplay() {
                const selectedList = $('#zipSelectedList');
                if (zipSelectedItems.size === 0) {
                    selectedList.html('<div class="zip-selected-empty">No items selected</div>');
                    return;
                }
                
                let html = '';
                const sortedItems = Array.from(zipSelectedItems).sort();
                for (const itemPath of sortedItems) {
                    const fileName = itemPath.split('/').pop() || itemPath;
                    const isFolder = itemPath.endsWith('/') || !itemPath.includes('.');
                    const icon = isFolder ? '📁' : '📄';
                    
                    html += `<div class="zip-item">
                        <span class="zip-item-icon">${icon}</span>
                        <span class="zip-item-text">${escapeHtml(fileName)}</span>
                        <button type="button" class="removeZipItem remove-btn" data-path="${escapeHtml(itemPath)}"><i class="fa-solid fa-trash"></i></button>
                    </div>`;
                }
                selectedList.html(html);
                
                // Attach remove buttons
                selectedList.find('.removeZipItem').off('click').on('click', function() {
                    const path = $(this).data('path');
                    zipSelectedItems.delete(path);
                    updateZipSelectedCount();
                    // Update checkbox state if it exists
                    const checkbox = $(`input[value="${path}"]`);
                    if (checkbox.length) {
                        checkbox.prop('checked', false);
                        const itemDiv = checkbox.closest('div');
                        if (itemDiv.length) itemDiv.css('background', '#fff');
                    }
                });
            }

            function loadZipItems(dir = '') {
                currentZipDir = dir;
                $.get('?listdir=1&dir=' + encodeURIComponent(dir), function(data) {
                    if (data.error) {
                        $('#zipItemsList').html('<div class="zip-error">' + escapeHtml(data.error) + '</div>');
                        $('#zipPath').text('');
                        return;
                    }
                    
                    // Generate breadcrumb navigation for ZIP browser
                    let breadcrumbHtml = '<div class="zip-breadcrumb-container" style="background: #f8f9fa; padding: 8px; border-radius: 4px; border: 1px solid #e9ecef; margin-bottom: 10px; font-size: 12px;">';
                    breadcrumbHtml += '<span style="font-weight: bold; color: #495057;">Path: </span>';
                    
                    if (!dir || dir === '') {
                        breadcrumbHtml += '<a href="#" class="zip-breadcrumb-link" data-dir="" style="color: #0073e6; text-decoration: none; font-weight: bold;">🏠 Root</a>';
                    } else {
                        const pathParts = dir.split('/').filter(part => part !== '');
                        breadcrumbHtml += '<a href="#" class="zip-breadcrumb-link" data-dir="" style="color: #0073e6; text-decoration: none; font-weight: bold;">🏠 Root</a>';
                        
                        let currentPath = '';
                        for (let i = 0; i < pathParts.length; i++) {
                            currentPath += (currentPath ? '/' : '') + pathParts[i];
                            const isLast = i === pathParts.length - 1;
                            const linkStyle = isLast ? 'color: #495057; text-decoration: none; font-weight: bold;' : 'color: #0073e6; text-decoration: none;';
                            const separator = i < pathParts.length - 1 ? ' <span style="color: #6c757d; margin: 0 3px;">/</span> ' : '';
                            
                            if (isLast) {
                                breadcrumbHtml += separator + '<span style="' + linkStyle + '">📁 ' + escapeHtml(pathParts[i]) + '</span>';
                            } else {
                                breadcrumbHtml += separator + '<a href="#" class="zip-breadcrumb-link" data-dir="' + escapeHtml(currentPath) + '" style="' + linkStyle + '">📁 ' + escapeHtml(pathParts[i]) + '</a>';
                            }
                        }
                    }
                    breadcrumbHtml += '</div>';
                    
                    $('#zipPath').html(breadcrumbHtml);
                    let html = '';
                    
                    if (data.dir) {
                        const upDir = data.dir.split('/').slice(0, -1).join('/');
                        html += `<div class="zip-up-link">
                                <a href='#' class='zipUp' data-dir='${escapeHtml(upDir)}'><i class="fas fa-arrow-up"></i> Up</a>
                        </div>`;
                    }
                    
                    html += '<div class="zip-grid">';
                    const folders = data.items.filter(item => item.type === 'folder');
                    const files = data.items.filter(item => item.type === 'file');

                    folders.sort((a, b) => a.name.localeCompare(b.name));
                    files.sort((a, b) => a.name.localeCompare(b.name));

                    const renderItem = (item) => {
                        const isSelected = zipSelectedItems.has(item.path);
                        const itemId = 'zipitem_' + btoa(item.path).replace(/[^a-z0-9]/gi, '');
                        const icon = item.type === 'folder' ? '📁' : '📄';
                        
                        return `<div class='zip-browse-item ${isSelected ? 'selected' : ''}'>
                            <input type='checkbox' id='${itemId}' value='${escapeHtml(item.path)}' ${isSelected ? 'checked' : ''} class="zip-checkbox">
                            <span class='zip-browse-text' onclick="document.getElementById('${itemId}').click()">
                                ${icon} ${escapeHtml(item.name)}
                            </span>
                            ${item.type === 'folder' ? `<button type='button' class='zipBrowseDir zip-browse-btn' data-dir='${escapeHtml(item.path)}'>Browse</button>` : ''}
                        </div>`;
                    };

                    folders.forEach(item => html += renderItem(item));
                    files.forEach(item => html += renderItem(item));

                    html += '</div>';
                    $('#zipItemsList').html(html);
                    
                    // Attach event listeners
                    $('#zipItemsList input[type="checkbox"]').off('change').on('change', function() {
                        if (this.checked) {
                            zipSelectedItems.add(this.value);
                        } else {
                            zipSelectedItems.delete(this.value);
                        }
                        updateZipSelectedCount();
                        // Update visual state
                        const itemDiv = $(this).closest('div');
                        if (this.checked) {
                            itemDiv.css('background', '#e8f5e8');
                        } else {
                            itemDiv.css('background', '#fff');
                        }
                    });
                    
                    // Directory navigation
                    $('#zipItemsList .zipUp, #zipItemsList .zipBrowseDir').off('click').on('click', function(e) {
                        e.preventDefault();
                        loadZipItems($(this).data('dir'));
                    });
                    // ZIP breadcrumb navigation
                    $('.zip-breadcrumb-link').off('click').on('click', function(e) {
                        e.preventDefault();
                        loadZipItems($(this).data('dir'));
                    });
                });
            }

            // Event listeners
            $('#openZipBrowser').off('click').on('click', function() {
                zipSelectedItems.clear();
                loadZipItems('');
                showZipModal();
                refreshZipFilesList();
                updateZipSelectedCount();
            });

            function showZipModal() {
                Swal.fire({
                    title: 'Zip Files or Folders',
                    html: `
                        <div id="zipFilesArea" class="zip-modal-section"></div>
                        <div id="zipPath" class="zip-path"></div>
                        
                        <div class="zip-modal-grid">
                            <div>
                                <h3 class="zip-modal-title">📂 Browse Files & Folders</h3>
                                
                                <!-- Search and Filter Controls -->
                                <div class="zip-search-section mb-3">
                                    <div class="form-group">
                                        <div class="input-group">
                                            <input type="text" id="zipSearchInput" class="form-control form-control-md" placeholder="Search files and folders...">
                                        
                                            <button id="zipSearchBtn" class="btn btn-primary btn-md">
                                                <i class="fas fa-search"></i> Search
                                            </button>
                                        </div>
                                    </div>
                                </div>
                                
                                <div id="zipItemsList" class="zip-items-list"></div>
                                <div class="btn-group mt-3" role="group" aria-label="Action">
                                    <button type="button" id="backToRootZip" class="btn zip-btn"><i class="fa-solid fa-home"></i> Root</button>                                    
                                    <button type="button" id="selectAllZipItems" class="btn zip-btn zip-btn-success"><i class="fa-regular fa-square-check"></i> Select All</button>
                                    <button type="button" id="deselectAllZipItems" class="btn zip-btn zip-btn-danger"><i class="fa-solid fa-xmark"></i> Deselect All</button>
                                </div>
                            </div>
                            
                            <div>
                                <h3 class="zip-modal-title">📋 Selected Items (<span id="zipSelectedCount">0</span>)</h3>
                                <div id="zipSelectedList" class="zip-selected-list">
                                    <div class="zip-selected-empty">No items selected</div>
                                </div>
                            </div>
                        </div>
                        
                        <div id="zipResult" class="zip-result"></div>
                    `,
                    showCancelButton: true,
                    confirmButtonText: '<i class="fa-regular fa-file-zipper"></i> Create Zip',
                    cancelButtonText: '<i class="fa-solid fa-xmark"></i> Cancel',
                    confirmButtonColor: '#008000',
                    cancelButtonColor: '#ff6b6b',
                    allowOutsideClick: false,
                    allowEscapeKey: false,
                    width: '800px',
                    didOpen: () => {
                        // Attach button events
                        $('#backToRootZip').off('click').on('click', function() {
                            loadZipItems(''); // Go back to root directory
                        });

                        $('#selectAllZipItems').off('click').on('click', function() {
                            $('#zipItemsList input[type="checkbox"]').prop('checked', true).trigger('change');
                        });

                        $('#deselectAllZipItems').off('click').on('click', function() {
                            $('#zipItemsList input[type="checkbox"]').prop('checked', false).trigger('change');
                        });
                        
                        // ZIP Search functionality
                        $('#zipSearchBtn').off('click').on('click', function() {
                            const searchTerm = $('#zipSearchInput').val().trim();
                            
                            // If no search term and no filter, just reload current directory
                            if (!searchTerm) {
                                loadZipItems(currentZipDir);
                                return;
                            }
                            
                            // If no search term but has filter, use empty pattern to get all files
                            if (!searchTerm) {
                                searchTerm = '';
                            }
                            
                            // Show loading
                            $('#zipItemsList').html('<div class="text-center"><i class="fas fa-spinner fa-spin"></i> Searching...</div>');
                            
                            const params = {
                                type: 'name',
                                pattern: searchTerm,
                                directory: '', // Always search from root directory
                                recursive: '1'
                            };
                            
                            $.get('?search_files=1', params, function(response) {
                                
                                if (response.results && response.results.length > 0) {
                                    let filteredResults = response.results;

                                    
                                    // Display search results
                                    let searchResultsHtml = '';
                                    filteredResults.forEach(function(item) {
                                        const itemId = `zip_${btoa(item.path).replace(/[^a-z0-9]/gi, '')}`;
                                        const icon = item.type === 'folder' ? '📁' : '📄';
                                        const size = item.size ? formatFileSize(item.size) : '';
                                        
                                        searchResultsHtml += `
                                            <div class="zip-browse-item">
                                                <input type="checkbox" id="${itemId}" class="zip-checkbox" data-path="${normalizePathSlashes(item.path)}">
                                                <label for="${itemId}">
                                                    <span class="zip-browse-text">${icon} ${item.name}</span>
                                                    <small class="text-muted">${item.path}</small>
                                                    ${size ? `<small class="text-muted">(${size})</small>` : ''}
                                                </label>
                                            </div>`;
                                    });
                                    
                                    if (searchResultsHtml) {
                                        $('#zipItemsList').html(searchResultsHtml);
                                        // Re-bind checkbox events
                                        $('.zip-checkbox').off('change').on('change', function() {
                                            const path = $(this).data('path');
                                            if (this.checked) {
                                                zipSelectedItems.add(path);
                                            } else {
                                                zipSelectedItems.delete(path);
                                            }
                                            updateZipSelectedCount();
                                        });
                                    } else {
                                        $('#zipItemsList').html('<div class="text-center">No items found matching your criteria.</div>');
                                    }
                                } else {
                                    $('#zipItemsList').html('<div class="text-center">No items found matching your criteria.</div>');
                                }
                            }).fail(function() {
                                $('#zipItemsList').html('<div class="text-center text-danger">Search failed. Please try again.</div>');
                            });
                        });
                    },
                    preConfirm: () => {
                        if (zipSelectedItems.size === 0) {
                            showNotification('Please select at least one file or folder.', 'error');
                            return false;
                        }

                        return Swal.fire({
                            title: 'Enter Zip File Name',
                            input: 'text',
                            inputValue: `archive_${new Date().toISOString().slice(0, 10)}.zip`,
                            showCancelButton: true,
                            confirmButtonText: '<i class="fa-regular fa-file-zipper"></i> Create Zip',
                            cancelButtonColor: '#ff6b6b',
                            confirmButtonColor: '#008000',
                            inputValidator: (value) => {
                                if (!value || !value.endsWith('.zip')) {
                                    return 'Please enter a valid name ending with .zip';
                                }
                            }
                        }).then((result) => {
                            if (!result.isConfirmed) {
                                return false; // Abort if cancelled
                            }
                            const zipName = result.value;
                            const resultDiv = $('#zipResult');
                            
                            // Show progress modal
                            Swal.fire({
                                title: 'Creating ZIP File',
                                html: `
                                    <div class="text-center">
                                        <div class="spinner-border text-primary mb-3" role="status">
                                            <span class="visually-hidden"><i class="fas fa-spinner fa-spin"></i> Loading...</span>
                                        </div>
                                        <p>Creating zip file: <strong>${escapeHtml(zipName)}</strong></p>
                                        <p class="text-muted">Please wait, this may take a moment...</p>
                                    </div>
                                `,
                                allowOutsideClick: false,
                                allowEscapeKey: false,
                                showConfirmButton: false,
                                didOpen: () => {
                                    Swal.showLoading();
                                }
                            });
                            
                            const formData = new FormData();
                            Array.from(zipSelectedItems).forEach(item => formData.append('items[]', item));
                            formData.append('zipName', zipName);
                            
                            return $.ajax({
                                url: '?zip_create=1',
                                method: 'POST',
                                data: formData,
                                processData: false,
                                contentType: false
                            }).then(data => {
                                // Close progress modal
                                Swal.close();
                                
                                if (data.download_url) {
                                    // Show success toast with appropriate message
                                    let toastMessage = `ZIP file "${zipName}" created successfully!`;
                                    if (data.name_changed) {
                                        toastMessage = `ZIP file created as "${data.new_name}" (original name "${data.original_name}" was already taken)`;
                                    }
                                    
                                    showNotification(toastMessage, 'success');
                                    
                                    // Update result div
                                    let resultHtml = `<div class="zip-success"><i class="fas fa-check-circle"></i> Zip created successfully!</div>`;
                                    if (data.name_changed) {
                                        resultHtml += `<div class="zip-info"><i class="fas fa-edit"></i> File saved as: <strong>${data.new_name}</strong></div>`;
                                    }
                                    resultHtml += `<a href="${data.download_url}" class="zip-download-link"><i class="fas fa-download"></i> Download Zip File</a>`;
                                    resultDiv.html(resultHtml);
                                    
                                    // Refresh and highlight new file
                                    refreshZipFilesList(data.new_name || zipName);
                                    
                                    // Close modal after success
                                    setTimeout(() => {
                                        Swal.close();
                                    }, 2000);
                                    
                                    return true;
                                } else if (data.error) {
                                    // Show error toast
            
                                    showNotification(data.error, 'error');
                                    
                                    resultDiv.html('<span class="zip-error"><i class="fas fa-exclamation-triangle"></i> ' + escapeHtml(data.error) + '</span>');
                                    return false;
                                } else {
                                    // Show error toast
                                    showNotification('Unknown error occurred while creating ZIP file', 'error');
                                    
                                    resultDiv.html('<span class="zip-error"><i class="fas fa-exclamation-triangle"></i> Unknown error occurred.</span>');
                                    return false;
                                }
                            }).catch((error) => {
                                // Close progress modal
                                Swal.close();
                                
                                // Show error toast
                                let errorMsg = '';
                                if (typeof error === 'string') {
                                    errorMsg = error;
                                } else if (error && error.message) {
                                    errorMsg = error.message;
                                } else if (error && error.responseText) {
                                    try {
                                        const response = JSON.parse(error.responseText);
                                        errorMsg = response.error || 'Request failed';
                                    } catch (e) {
                                        errorMsg = error.responseText || 'Request failed';
                                    }
                                } else {
                                    errorMsg = 'Request failed';
                                }
                                showNotification(errorMsg, 'error');
                                
                                resultDiv.html('<span class="zip-error"><i class="fas fa-exclamation-triangle"></i> ' + errorMsg + '</span>');
                                return false;
                            });
                        });
                    }
                });
            }

            // --- Zip files list logic ---
            function refreshZipFilesList(highlightFile = null) {
                const area = $('#zipFilesArea');
                area.html('<div class="zip-loading"><i class="fas fa-spinner fa-spin"></i> Loading zip files...</div>');
                
                // Use cached data if available and valid
                const now = Date.now();
                const cacheValid = (now - dashboardCache.lastUpdate) < dashboardCache.cacheTimeout;
                
                if (cacheValid && dashboardCache.zips) {
                    updateZipFilesDisplay(dashboardCache.zips, highlightFile);
                    return;
                }
                
                $.get('?list_zips=1', function(data) {
                    dashboardCache.zips = data;
                    dashboardCache.lastUpdate = now;
                    updateZipFilesDisplay(data, highlightFile);
                }).fail(() => {
                    area.html('<div class="zip-error">Failed to load zip files.</div>');
                });
            }
            
            function updateZipFilesDisplay(data, highlightFile = null) {
                const area = $('#zipFilesArea');
                
                if (!data.zips || data.zips.length === 0) {
                    area.html('<div class="zip-files-empty c-grey">No zip files found.</div>');
                    return;
                }
                
                let html = '<div class="zip-files-title">Existing Zip Files:</div>';
                html += '<ul class="zip-files-list">';
                for (const zip of data.zips) {
                    const isHighlighted = highlightFile && zip.name === highlightFile;
                    const highlightClass = isHighlighted ? 'zip-file-item-new' : '';
                    html += `<li class="zip-file-item ${highlightClass}" data-filename="${escapeHtml(zip.name)}">
                        <div class="zip-file-info">
                            <span class="zip-file-icon"><i class="fas fa-archive"></i></span>
                            <a href="${zip.download_url}" class="zip-file-link">${escapeHtml(zip.name)}</a>
                            ${isHighlighted ? '<span class="zip-file-new-badge"><i class="fas fa-star"></i> NEW</span>' : ''}
                        </div>
                        <div class="zip-file-actions">
                            <button class="btn btn-md btn-primary zip-action-btn" onclick="downloadZip('${escapeHtml(zip.name)}')" title="Download">
                                <i class="fas fa-download"></i>
                            </button>
                            <button class="btn btn-md btn-info zip-action-btn" onclick="extractZip('${escapeHtml(zip.name)}')" title="Extract">
                                <i class="fas fa-folder-open"></i>
                            </button>
                            <button class="btn btn-md btn-danger zip-action-btn" onclick="deleteZip('${escapeHtml(zip.name)}')" title="Delete">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </li>`;
                }
                html += '</ul>';
                area.html(html);
                
                // Add animation for highlighted file
                if (highlightFile) {
                    setTimeout(() => {
                        const highlightedItem = $(`.zip-file-item[data-filename="${escapeHtml(highlightFile)}"]`);
                        if (highlightedItem.length) {
                            highlightedItem.addClass('zip-file-item-highlighted');
                            // Remove highlight after 5 seconds
                            setTimeout(() => {
                                highlightedItem.removeClass('zip-file-item-highlighted zip-file-item-new');
                                highlightedItem.find('.zip-file-new-badge').remove();
                            }, 5000);
                        }
                    }, 100);
                }
            }

            // Initialize zip files list on page load
            refreshZipFilesList();

            // Global ZIP file action functions
            window.downloadZip = function(zipName) {
                window.open('?zip_download=1&file=' + encodeURIComponent(zipName), '_blank');
            };

            window.deleteZip = function(zipName) {
                Swal.fire({
                    title: 'Delete ZIP File',
                    text: `Are you sure you want to delete "${zipName}"?`,
                    icon: 'warning',
                    showCancelButton: true,
                    confirmButtonText: '<i class="fas fa-trash"></i> Delete',
                    cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                    confirmButtonColor: '#dc3545',
                    cancelButtonColor: '#6c757d',
                    allowOutsideClick: false,
                    allowEscapeKey: false,
                }).then((result) => {
                    if (result.isConfirmed) {
                        // Show loading state
                        Swal.fire({
                            title: 'Deleting ZIP File',
                            html: 'Please wait...',
                            allowOutsideClick: false,
                            allowEscapeKey: false,
                            didOpen: () => {
                                Swal.showLoading()
                            }
                        });

                        $.ajax({
                            url: '?delete_zip=1',
                            method: 'POST',
                            data: { zipName: zipName },
                            dataType: 'json',
                            success: function(data) {
                                Swal.close();
                                if (data.success) {
                                    showNotification(`ZIP file "${zipName}" deleted successfully!`, 'success');
                                    
                                    // Invalidate cache and refresh the list
                                    dashboardCache.zips = null;
                                    refreshZipFilesList();
                                } else {
                                    showNotification(data.error || 'Failed to delete ZIP file', 'error');
                                }
                            },
                            error: function(xhr, status, error) {
                                Swal.close();
                                let errorMsg = '';
                                try {
                                    const response = JSON.parse(xhr.responseText);
                                    errorMsg = response.error || error || 'Request failed';
                                } catch (e) {
                                    errorMsg = xhr.responseText || error || 'Request failed';
                                }
                                showNotification(errorMsg, 'error');
                            }
                        });
                    }
                });
            };

            window.extractZip = function(zipName) {
                // Use the same folder browser UI as browseFolders()
                openExtractBrowserModal(zipName);
            };

            function openExtractBrowserModal(zipName) {
                let currentDir = '';

                function bindExtractBrowserEvents() {
                    // Re-bind events for the control buttons
                    $('#backToRootBrowser').off('click').on('click', function() {
                        loadExtractDir(''); // Go back to root directory
                    });
                    
                    $('#extractHere').off('click').on('click', function() {
                        // Extract to current directory
                        performExtractToPath(zipName, currentDir);
                    });

                    // Search functionality
                    $('#browserSearchBtn').off('click').on('click', function() {
                        const searchTerm = $('#browserSearchInput').val().trim();
                        
                        // If no search term, just reload current directory
                        if (!searchTerm) {
                            loadExtractDir(currentDir);
                            return;
                        }
                        
                        // Show loading
                        $('#browserResults').html('<div class="text-center"><i class="fas fa-spinner fa-spin"></i> Searching...</div>');
                        
                        const params = {
                            type: 'name',
                            pattern: searchTerm,
                            directory: '', // Always search from root directory
                            recursive: '1'
                        };
                        
                        $.get('?search_files=1', params, function(response) {
                            if (response.results && response.results.length > 0) {
                                let filteredResults = response.results;
                                
                                // Only show folders for extract
                                const folders = filteredResults.filter(item => item.type === 'folder');
                                
                                // Display search results
                                let searchResultsHtml = '';
                                
                                folders.forEach(function(item) {
                                    const itemId = `folder_${btoa(item.path).replace(/[^a-z0-9]/gi, '')}`;
                                    const icon = '📁';
                                    
                                    searchResultsHtml += `
                                        <div class='browser-item'>
                                            <a href='#' class='browserDir' data-path='${normalizePathSlashes(item.path)}'>${icon} ${item.name}</a>
                                            <small class="text-muted">${item.path}</small>
                                        </div>`;
                                });
                                
                                if (searchResultsHtml) {
                                    $('#browserResults').html(searchResultsHtml);
                                    bindExtractBrowserEvents(); // Re-bind events for new elements
                                } else {
                                    $('#browserResults').html('<div class="text-center">No folders found matching your criteria.</div>');
                                }
                            } else {
                                $('#browserResults').html('<div class="text-center">No folders found matching your criteria.</div>');
                            }
                        }).fail(function() {
                            $('#browserResults').html('<div class="text-center text-danger">Search failed. Please try again.</div>');
                        });
                    });

                    // Re-bind events for directory navigation
                    $('.browserDir').off('click').on('click', function(e) {
                        e.preventDefault();
                        loadExtractDir($(this).data('path'));
                    });
                    $('.browserUp').off('click').on('click', function(e) {
                        e.preventDefault();
                        let up = currentDir.split('/').slice(0, -1).join('/');
                        loadExtractDir(up);
                    });
                    // Extract breadcrumb navigation
                    $('.extract-breadcrumb-link').off('click').on('click', function(e) {
                        e.preventDefault();
                        loadExtractDir($(this).data('dir'));
                    });
                    
                    // Double-click to select folder for extract
                    $('.browserDir').off('dblclick').on('dblclick', function(e) {
                        e.preventDefault();
                        let path = $(this).data('path');
                        performExtractToPath(zipName, path);
                    });
                }

                function loadExtractDir(dir) {
                    $.get('?listdir=1&dir=' + encodeURIComponent(dir), function(resp) {
                        currentDir = dir;
                        
                        // Generate breadcrumb navigation for extract browser
                        let breadcrumbHtml = '<div class="extract-breadcrumb-container mb-3" style="background: #f8f9fa; padding: 8px; border-radius: 6px; border: 1px solid #e9ecef;font-size: 12px;">';
                        breadcrumbHtml += '<span style="font-weight: bold; color: #495057;">Extract Path: </span>';
                        
                        if (!dir || dir === '') {
                            breadcrumbHtml += '<a href="#" class="extract-breadcrumb-link" data-dir="" style="color: #0073e6; text-decoration: none; font-weight: bold;">🏠 Root</a>';
                        } else {
                            const pathParts = dir.split('/').filter(part => part !== '');
                            breadcrumbHtml += '<a href="#" class="extract-breadcrumb-link" data-dir="" style="color: #0073e6; text-decoration: none; font-weight: bold;">🏠 Root</a>';
                            
                            let currentPath = '';
                            for (let i = 0; i < pathParts.length; i++) {
                                currentPath += (currentPath ? '/' : '') + pathParts[i];
                                const isLast = i === pathParts.length - 1;
                                const linkStyle = isLast ? 'color: #495057; text-decoration: none; font-weight: bold;' : 'color: #0073e6; text-decoration: none;';
                                const separator = i < pathParts.length - 1 ? ' <span style="color: #6c757d; margin: 0 5px;">/</span> ' : '';
                                
                                if (isLast) {
                                    breadcrumbHtml += separator + '<span style="' + linkStyle + '">📁 ' + escapeHtml(pathParts[i]) + '</span>';
                                } else {
                                    breadcrumbHtml += separator + '<a href="#" class="extract-breadcrumb-link" data-dir="' + escapeHtml(currentPath) + '" style="' + linkStyle + '">📁 ' + escapeHtml(pathParts[i]) + '</a>';
                                }
                            }
                        }
                        breadcrumbHtml += '</div>';
                        
                        let fileListHtml = '';
                        if (dir) {
                            fileListHtml += `<div class='browser-item'><a href='#' class='browserUp'>.. <i class="fa-solid fa-turn-up"></i> (Up)</a></div>`;
                        }
                        
                        // Only show folders for extract
                        let folders = resp.items.filter(i => i.type === 'folder').sort((a, b) => a.name.localeCompare(b.name));
                        
                        folders.forEach(function(item) {
                            fileListHtml += `
                                <div class='browser-item'>
                                    <a href='#' class='browserDir' data-path='${normalizePathSlashes(item.path)}'>📁 ${item.name}</a>
                                </div>`;
                        });

                        const modalHtml = `
                            <div class="browser-search-section mb-3">
                                <div class="row">
                                    <div class="col-md-9">
                                        <input type="text" id="browserSearchInput" class="form-control form-control-md" placeholder="Search folders...">
                                    </div>
                                    <div class="col-md-3">
                                        <button id="browserSearchBtn" class="btn btn-primary btn-md w-100">
                                            <i class="fas fa-search"></i> Search
                                        </button>
                                    </div>
                                </div>
                            </div>
                            ${breadcrumbHtml}
                            <div class="text-right mb-3">
                                <button id="backToRootBrowser" class="btn btn-info btn-lg me-2">
                                    <i class="fa-solid fa-home"></i> Root
                                </button>
                                <button id="extractHere" class="btn btn-primary btn-lg">
                                    <i class="fas fa-folder-open"></i> Extract Here
                                </button>
                            </div>
                            <div id="browserResults" style='max-height:300px;overflow:auto;'>${fileListHtml}</div>
                        `;
                        
                        if (Swal.isVisible()) {
                            Swal.update({ html: modalHtml });
                            bindExtractBrowserEvents();
                        } else {
                            Swal.fire({
                                title: 'Choose Extract Location',
                                html: modalHtml,
                                showCancelButton: true,
                                cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                                cancelButtonColor: '#ff6b6b',
                                showConfirmButton: false,
                                allowOutsideClick: false,
                                allowEscapeKey: false,
                                customClass: {
                                    header: 'swal2-header-with-root-button'
                                },
                                didOpen: () => {
                                    bindExtractBrowserEvents();
                                }
                            });
                        }
                    });
                }
                loadExtractDir(currentDir);
            }

            function performExtractToPath(zipName, extractPath) {
                // Close the browser modal
                Swal.close();
                
                // Perform the extract directly to the selected path
                checkAndExtract(zipName, extractPath);
            }

            function showSimpleExtractDialog(zipName) {
                Swal.fire({
                    title: 'Extract ZIP File',
                    html: `
                        <div class="form-group">
                            <label for="extractPath" class="form-label">Extract to directory:</label>
                            <input type="text" id="extractPath" class="form-control" 
                                   placeholder="e.g., extracted_files, backup_2024, etc." 
                                   value="">
                            <small class="form-text text-muted">
                                Enter a directory path or leave empty to extract to root directory.
                            </small>
                        </div>
                    `,
                    showCancelButton: true,
                    confirmButtonText: '<i class="fas fa-folder-open"></i> Extract',
                    cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                    customClass: {
                        confirmButton: 'btn btn-lg btn-primary',
                        cancelButton: 'btn btn-lg btn-secondary'
                    },
                    confirmButtonColor: '#17a2b8',
                    cancelButtonColor: '#ff6b6b',
                    allowOutsideClick: false,
                    allowEscapeKey: false,
                    preConfirm: () => {
                        const extractPath = document.getElementById('extractPath').value.trim();
                        if (!extractPath) {
                            Swal.showValidationMessage('Please enter an extract path');
                            return false;
                        }
                        return extractPath;
                    }
                }).then((result) => {
                    if (result.isConfirmed) {
                        const extractPath = result.value;
                        checkAndExtract(zipName, extractPath);
                    }
                });
            }

            function checkAndExtract(zipName, extractPath) {
                // First check if directory exists and has content
                $.post('?check_extract_path=1', {
                    extractPath: extractPath
                }, function(response) {
                    if (response.exists && response.hasContent) {
                        // Directory exists and has content - ask user what to do
                        Swal.fire({
                            title: 'Directory Already Exists',
                            html: `
                                <div class="text-center">
                                    <i class="fas fa-exclamation-triangle text-warning" style="font-size: 3rem; margin-bottom: 1rem;"></i>
                                    <p><strong>${extractPath}</strong> already exists and contains files.</p>
                                    <p class="text-muted">What would you like to do?</p>
                                </div>
                            `,
                            showCancelButton: true,
                            showDenyButton: true,
                            showCloseButton: true,
                            confirmButtonText: '<i class="fas fa-sync-alt"></i> Merge & Replace',
                            denyButtonText: '<i class="fas fa-folder-plus"></i> Create New',
                            cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                            customClass: {
                                confirmButton: 'btn btn-lg btn-primary',
                                denyButton: 'btn btn-lg btn-success',
                                cancelButton: 'btn btn-lg btn-secondary'
                            },
                            confirmButtonColor: '#17a2b8',
                            denyButtonColor: '#28a745',
                            cancelButtonColor: '#ff6b6b',
                            allowOutsideClick: false,
                            allowEscapeKey: false
                        }).then((result) => {
                            if (result.isConfirmed) {
                                // Merge and replace only conflicting files
                                performExtract(zipName, extractPath, 'merge');
                            } else if (result.isDenied) {
                                // Create new directory with timestamp
                                const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
                                const newPath = extractPath + '_' + timestamp;
                                performExtract(zipName, newPath, 'new');
                            }
                        });
                    } else if (response.exists && !response.hasContent) {
                        // Directory exists but is empty - proceed
                        performExtract(zipName, extractPath, 'empty');
                    } else {
                        // Directory doesn't exist - proceed
                        performExtract(zipName, extractPath, 'new');
                    }
                }).fail(function() {
                    // If check fails, proceed with extraction
                    performExtract(zipName, extractPath, 'unknown');
                });
            }

            function performExtract(zipName, extractPath, mode) {
                let actionText = '';
                switch(mode) {
                    case 'overwrite': actionText = 'Overwriting existing directory'; break;
                    case 'merge': actionText = 'Merging files (replacing conflicts)'; break;
                    case 'new': actionText = 'Creating new directory'; break;
                    case 'empty': actionText = 'Extracting to empty directory'; break;
                    default: actionText = 'Extracting files'; break;
                }

                Swal.fire({
                    title: 'Extracting ZIP File',
                    html: `
                        <div class="text-center">
                            <div class="spinner-border text-primary mb-3" role="status">
                                <span class="visually-hidden"><i class="fas fa-spinner fa-spin"></i> Loading...</span>
                            </div>
                            <p>${actionText}</p>
                            <p><strong>${zipName}</strong> → <strong>${extractPath}</strong></p>
                            <p class="text-muted">Please wait, this may take a moment...</p>
                        </div>
                    `,
                    allowOutsideClick: false,
                    allowEscapeKey: false,
                    didOpen: () => {
                        Swal.showLoading();
                    }
                });

                $.ajax({
                    url: '?extract_zip=1',
                    method: 'POST',
                    data: { 
                        zipName: zipName,
                        extractPath: extractPath,
                        mode: mode
                    },
                    dataType: 'json',
                    success: function(data) {
                        Swal.close();
                        if (data.success) {
                            let message = `ZIP file "${zipName}" extracted successfully!`;
                            if (mode === 'overwrite') {
                                message += ' (Existing files were overwritten)';
                            } else if (mode === 'merge') {
                                message += ' (Files merged - conflicts were replaced)';
                            } else if (mode === 'new') {
                                if (extractPath) {
                                    message += ` (Created new directory: ${extractPath})`;
                                } else {
                                    message += ' (Extracted to root directory)';
                                }
                            } else if (!extractPath) {
                                message += ' (Extracted to root directory)';
                            }
                            showNotification(message, 'success');
                        } else {
                            showNotification(data.error || 'Failed to extract ZIP file', 'error');
                        }
                    },
                    error: function(xhr, status, error) {
                        Swal.close();
                        let errorMsg = '';
                        try {
                            const response = JSON.parse(xhr.responseText);
                            errorMsg = response.error || error || 'Request failed';
                        } catch (e) {
                            errorMsg = xhr.responseText || error || 'Request failed';
                        }
                        showNotification(errorMsg, 'error');
                    }
                });
            }

            // --- REPLACE CORE ---
            $('#downloadWPBtn').on('click', function() {
                Swal.fire({
                    title: 'Replace WordPress Cores',
                    text: 'This will replace your WordPress core files. Are you sure?',
                    icon: 'warning',
                    showCancelButton: true,
                    confirmButtonText: '<i class="fas fa-sync-alt"></i> Replace',
                    cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                    confirmButtonColor: '#008000',
                    cancelButtonColor: '#ff6b6b',
                    allowOutsideClick: false,
                    allowEscapeKey: false,
                }).then((result) => {
                    if (result.isConfirmed) {
                        // Show loading state
                        Swal.fire({
                            title: 'Replacing WordPress Cores',
                            html: 'Please wait...',
                            allowOutsideClick: false,
                            allowEscapeKey: false,
                            didOpen: () => {
                                Swal.showLoading()
                            }
                        });

                        $.ajax({
                            url: '?download_wp=1',
                            method: 'POST',
                            data: {},
                            dataType: 'json',
                            timeout: 300000, // 5-minute timeout
                            success: function(resp) {
                                Swal.close();
                                if (resp && resp.success) {
                                    showNotification('WordPress core files replaced successfully!', 'success');
                                } else if (resp && resp.error) {
                                    let errorMsg = '';
                                    if (typeof resp.error === 'string') {
                                        errorMsg = resp.error;
                                    } else if (resp.error && resp.error.message) {
                                        errorMsg = resp.error.message;
                                    } else {
                                        errorMsg = JSON.stringify(resp.error);
                                    }
                                    showNotification('Failed: ' + errorMsg, 'error');
            
                                } else {
                                    showNotification('Server returned an invalid response. Please check console for details.', 'error');
            
                                }
                            },
                                                        error: function(xhr, status, error) {
                                Swal.close();

                                let errorMsg = '';

                                if (status === 'timeout') {
                                    errorMsg = 'Operation timed out. The server took too long to respond.';
                                } else if (xhr.status === 403) {
                                    errorMsg = 'Permission denied. Please check your credentials.';
                                } else if (xhr.status === 404) {
                                    errorMsg = 'Download endpoint not found. Please check server configuration.';
                                } else if (xhr.status === 500) {
                                    errorMsg = 'Server error occurred while processing the request.';
                                } else if (xhr.status === 0) {
                                    errorMsg = 'Network error or CORS issue. Please check your connection.';
                                } else {
                                    try {
                                        let json = JSON.parse(xhr.responseText);
                                        errorMsg = json.error || error || 'Unknown error occurred';
                                    } catch (e) {
                                        errorMsg = xhr.responseText || error || 'Unknown error occurred';
                                    }
                                }

                                showNotification('Error: ' + errorMsg, 'error');
                            }
                        });
                    }
                });
            });

            // --- PLUGIN CHECK/UPDATE ---
            $('#checkPluginsBtn').on('click', function() {
                Swal.fire({
                    title: 'Checking for Plugins',
                    html: 'Please wait...',
                    allowOutsideClick: false,
                    allowEscapeKey: false,
                    didOpen: () => {
                        Swal.showLoading()
                    }
                });
                $.ajax({
                    url: '?list_plugins=1',
                    method: 'GET',
                    headers: { 'X-Requested-With': 'XMLHttpRequest' },
                    success: function(resp) {
                        if (resp.plugins && resp.plugins.length) {
    
                            let html = `
                                <div class="text-right mb-2">
                                                                <button id="selectAllPlugins" class="btn btn-secondary btn-md">Select All</button>
                            <button id="deselectAllPlugins" class="btn btn-secondary btn-md">Deselect All</button>
                                </div>
                                <ul class='replace_plugins_list'>`;
                            resp.plugins.forEach(function(plugin) {
                                html += `<li><input id='${plugin.slug}' type='checkbox' class='pluginCheck' value='${plugin.slug}'> <a href='https://wordpress.org/plugins/${plugin.slug}' target="_blank">${plugin.name} <span style='color:#888;'>by ${plugin.author}</span></a></li>`;
                            });
                            html += '</ul>';
                            Swal.fire({
                                title: 'Replace Plugins',
                                html: html,
                                showCancelButton: true,
                                confirmButtonText: '<i class="fa-solid fa-wrench"></i> Update Selected',
                                cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                                confirmButtonColor: '#008000',
                                cancelButtonColor: '#ff6b6b',
                                allowOutsideClick: false,
                                allowEscapeKey: false,
                                didOpen: () => {
                                    $('#selectAllPlugins').on('click', function() {
                                        $('.pluginCheck').prop('checked', true);
                                    });
                                    $('#deselectAllPlugins').on('click', function() {
                                        $('.pluginCheck').prop('checked', false);
                                    });
                                },
                                preConfirm: () => {
                                    let slugs = [];
                                    $('.pluginCheck:checked').each(function() { slugs.push($(this).val()); });
                                    if (slugs.length === 0) {
                                        showNotification('Please select at least one plugin to replace.', 'error');
                                        return false; // Prevent modal from closing
                                    }
                                    return slugs;
                                }
                            }).then((result) => {
                                if (result.isConfirmed && result.value.length) {
                                    const slugs = result.value;
                                    let currentPluginIndex = 0;

                                    function updateNextPlugin() {
                                        if (currentPluginIndex >= slugs.length) {
                                            Swal.close();
                                            showNotification('All selected plugins replaced!', 'success');
                                            return;
                                        }

                                        const slug = slugs[currentPluginIndex];
                                        Swal.update({
                                            title: 'Replacing Plugins',
                                            html: `Replacing ${slug}... (${currentPluginIndex + 1} of ${slugs.length})`,
                                        });

                                        $.ajax({
                                            url: '?update_plugins=1',
                                            method: 'POST',
                                            contentType: 'application/json',
                                            headers: { 'X-Requested-With': 'XMLHttpRequest' },
                                            data: JSON.stringify({ slugs: [slug] }), // Send one at a time
                                            success: function(resp) {
                                                currentPluginIndex++;
                                                setTimeout(updateNextPlugin, 200); // Short delay between updates
                                            },
                                            error: function() {
                                                showNotification(`Failed to replace ${slug}`, 'error');
                                                currentPluginIndex++;
                                                setTimeout(updateNextPlugin, 200);
                                            }
                                        });
                                    }

                                    Swal.fire({
                                        title: 'Replacing Plugins',
                                        html: 'Preparing to replace plugins...',
                                        allowOutsideClick: false,
                                        allowEscapeKey: false,
                                        didOpen: () => {
                                            Swal.showLoading();
                                            updateNextPlugin();
                                        }
                                    });
                                }
                            });
                        } else {
                            Swal.close();
                            showNotification('No official plugins found.', 'info');
                        }
                    },
                    error: function(xhr) {
                        Swal.close();
                        showNotification('Failed to load plugins: ' + xhr.statusText, 'error');
                    }
                });
            });



            // --- Enter key handlers ---
            $('#folderPath').keypress(function(e) {
                if (e.which === 13) addFolder();
            });
            $('#filePath').keypress(function(e) {
                if (e.which === 13) addFile();
            });

            // Prevent form submission for delete
            $('#deleteForm').on('submit', function(e) {
                e.preventDefault();
                executeDelete();
            });

            // Utility: Normalize all backslashes to forward slashes
            function normalizePathSlashes(path) {
                return path.replace(/\\+/g, '/').replace(/\\/g, '/');
            }

            // Utility: Escape HTML to prevent XSS
            function escapeHtml(text) {
                const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
                return text.replace(/[&<>"']/g, m => map[m]);
            }
            // Expose to global scope so standalone script blocks (WP Toolkit) can reuse it.
            window.escapeHtml = escapeHtml;

            function renderBackups() {
                $.get('?list_backups=1', function(resp) {
                    let html = '';
                    if (!resp.backups || resp.backups.length === 0) {
                        html = '<div class="backup-empty c-grey">No backups found.</div>';
                    } else {
                        html += '<button class="btn btn-secondary btn-md" id="selectAllBackups" style="margin:4px 8px 4px 0;">Select All</button>';
                        html += '<button class="btn btn-primary btn-md" id="restoreSelectedBackups" style="margin:4px 8px 4px 0;">Restore Selected</button>';
                        html += '<button class="btn btn-danger btn-md" id="deleteSelectedBackups" style="margin:4px 0;">Delete Selected</button>';
                        html += '<ul style="margin-top:8px;list-style:none;">';
                        resp.backups.forEach(function(backup) {
                            const backupData = JSON.stringify(backup);
                            html += `<li><input type="checkbox" class="backupCheckbox" value="${backup.name}"> ${backup.name} (${backup.items.length} items)
                                                        <button class="btn btn-light btn-md viewBackupBtn" data-backup='${backup.name}' data-backup-data='${escapeHtml(backupData)}' style="margin-left:8px;"><i class='fas fa-eye'></i> View</button>
                        <button class="btn btn-primary btn-md restoreBackupBtn" data-backup="${backup.name}" style="margin-left:4px;">Restore</button>
                        <button class="btn btn-danger btn-md deleteBackupBtn" data-backup="${backup.name}" style="margin-left:4px;">Delete</button>
                            </li>`;
                        });
                        html += '</ul>';
                    }
                    $('#backupsList').html(html);
                    // Event handlers
                    $('#selectAllBackups').on('click', function() {
                        // Check if all checkboxes are checked
                        var isChecked = $('.backupCheckbox').not(':checked').length === 0;

                        // If all checkboxes are checked, uncheck them, and vice versa
                        if (isChecked) {
                            // Uncheck all checkboxes if they are all checked
                            $('.backupCheckbox').prop('checked', false);
                            $('#selectAllBackups').text('Select All');  // Optionally change button text
                        } else {
                            // Check all checkboxes if they are not all checked
                            $('.backupCheckbox').prop('checked', true);
                            $('#selectAllBackups').text('Deselect All');  // Optionally change button text
                        }
                    });
                    $('#restoreSelectedBackups').off('click').on('click', function() {
                        let selected = $('.backupCheckbox:checked').map(function() { return $(this).val(); }).get();
                        if (selected.length === 0) return showNotification('Select at least one backup', 'error');
                        Swal.fire({
                            title: 'Restore Selected Backups',
                            html: `<div style='text-align:left;'>Are you sure you want to restore <b>${selected.length}</b> backup(s)?</div>`,
                            icon: 'question',
                            showCancelButton: true,
                            confirmButtonText: 'Restore',
                            confirmButtonColor: '#0073e6',
                            cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                            cancelButtonColor: '#ff6b6b',
                            allowOutsideClick: false,
                            allowEscapeKey: false,
                        }).then((result) => {
                            if (result.isConfirmed) {
                                selected.forEach(function(name) { restoreBackup(name); });
                            }
                        });
                    });
                    $('#deleteSelectedBackups').off('click').on('click', function() {
                        let selected = $('.backupCheckbox:checked').map(function() { return $(this).val(); }).get();
                        if (selected.length === 0) return showNotification('Select at least one backup', 'error');
                        Swal.fire({
                            title: 'Delete Selected Backups',
                            html: `<div style='text-align:left;color:#c00;'>Are you sure you want to <b>permanently delete</b> <b>${selected.length}</b> backup(s)? This cannot be undone.</div>`,
                            icon: 'warning',
                            showCancelButton: true,
                            confirmButtonText: 'Delete',
                            confirmButtonColor: '#dc3545',
                            allowOutsideClick: false,
                            allowEscapeKey: false,
                        }).then((result) => {
                            if (result.isConfirmed) {
                                selected.forEach(function(name) { deleteBackup(name); });
                            }
                        });
                    });
                    $('.restoreBackupBtn').off('click').on('click', function() {
                        const name = $(this).data('backup');
                        Swal.fire({
                            title: 'Restore Backup',
                            html: `<div style='text-align:left;'>Restore backup <b>${name}</b>?</div>`,
                            icon: 'question',
                            showCancelButton: true,
                            confirmButtonText: '<i class="fas fa-sync-alt"></i> Restore',
                            confirmButtonColor: '#0073e6',
                            cancelButtonColor: '#888888',
                            cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                            allowOutsideClick: false,
                            allowEscapeKey: false,
                        }).then((result) => {
                            if (result.isConfirmed) restoreBackup(name);
                        });
                    });
                    $('.deleteBackupBtn').off('click').on('click', function() {
                        const name = $(this).data('backup');
                        Swal.fire({
                            title: 'Delete Backup',
                            html: `<div style='text-align:left;color:#c00;'>Delete backup <b>${name}</b>? This cannot be undone.</div>`,
                            icon: 'warning',
                            showCancelButton: true,
                            confirmButtonText: '<i class="fas fa-trash"></i> Delete',
                            confirmButtonColor: '#dc3545',
                            cancelButtonColor: '#888888',
                            cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                            allowOutsideClick: false,
                            allowEscapeKey: false,
                        }).then((result) => {
                            if (result.isConfirmed) deleteBackup(name);
                        });
                    });
                    $('.viewBackupBtn').off('click').on('click', function() {
                        const name = $(this).data('backup');
                        const backupData = $(this).data('backup-data');
                        if (!backupData) return;

                        let folders = backupData.items.filter(item => item.type === 'folder').sort((a, b) => a.name.localeCompare(b.name));
                        let files = backupData.items.filter(item => item.type === 'file').sort((a, b) => a.name.localeCompare(b.name));

                        let html = '<ul style="text-align:left;max-height:300px;overflow:auto;">';
                        folders.forEach(function(item) {
                            html += `<li><i class="fas fa-folder"></i> ${item.path}</li>`;
                        });
                        files.forEach(function(item) {
                            html += `<li><i class="fas fa-file"></i> ${item.path}</li>`;
                        });
                        html += '</ul>';

                        Swal.fire({
                            title: `<i class='fas fa-archive'></i> Backup: ${name}`,
                            html: html,
                            width: 600,
                            confirmButtonText: '<i class="fas fa-times"></i> Close',
                            confirmButtonColor: '#ff6b6b',
                            allowOutsideClick: false,
                            allowEscapeKey: false,
                            customClass: { confirmButton: 'btn btn-primary' }
                        });
                    });
                });
            }
            function restoreBackup(name) {
                const backupData = $('.viewBackupBtn[data-backup="' + name + '"]').data('backup-data');
                if (!backupData) {
                    showNotification('Could not find backup data to restore.', 'error');
                    return;
                }

                const itemsToRestore = backupData.items.map(item => item.path);

                // Start restore session
                $.post('?start_restore_backup=1', { 
                    backupDir: name, 
                    items: itemsToRestore 
                }, function(startResp) {
                    if (!startResp.sessionId) {
                        showNotification('Failed to start restore session', 'error');
                        return;
                    }
                    let sessionId = startResp.sessionId;
                    let total = startResp.total;
                    let processed = 0;

                    function processBatch() {
                        $.post('?process_restore_backup=1', { sessionId: sessionId }, function(procResp) {
                            if (procResp && procResp.busy) { setTimeout(processBatch, 300); return; }
                            processed += Object.keys(procResp.results || {}).length;
                            if (procResp.finished) {
                                showNotification('Backup restored successfully!', 'success');
                                Swal.close();
                                renderBackups(); // Refresh the list
                            } else {
                                Swal.update({
                                    title: 'Restoring from Backup',
                                    html: `<div>Restored ${processed} of ${total}...</div>`,
                                    showConfirmButton: false,
                                    allowOutsideClick: false,
                                    allowEscapeKey: false
                                });
                                setTimeout(processBatch, 200);
                            }
                        }).fail(function() {
                            showNotification('Error during batch restore', 'error');
                        });
                    }

                    Swal.fire({
                        title: 'Restoring from Backup',
                        html: `<div>Restored 0 of ${total}...</div>`,
                        showConfirmButton: false,
                        allowOutsideClick: false,
                        allowEscapeKey: false,
                        didOpen: () => {
                            Swal.showLoading();
                        }
                    });

                    processBatch();
                });
            }
            function deleteBackup(name) {
                $.post('?delete_backup=1', { backupDir: name }, function(resp) {
                    if (resp.success) {
                        showNotification('Backup deleted!', 'success');
                        renderBackups();
                    } else {
                        showNotification('Failed: ' + (resp.error || 'Unknown error'), 'error');
                    }
                });
            }

            function renderTrash() {
                $.get('?list_trash=1', function(resp) {
                    let html = '';
                    if (!resp.items || resp.items.length === 0) {
                        html = '<div class="c-grey">Trash is empty.</div>';
                    } else {
                                        html += '<button class="btn btn-secondary btn-md" id="selectAllTrash" style="margin:4px 8px 4px 0;">Select All</button>';
                html += '<button class="btn btn-primary btn-md" id="restoreSelectedTrash" style="margin:4px 8px 4px 0;">Restore Selected</button>';
                html += '<button class="btn btn-danger btn-md" id="deleteSelectedTrash" style="margin:4px 0;">Delete Selected</button>';
                        html += '<ul style="margin-top:8px;list-style:none;">';
                        
                        let folders = resp.items.filter(item => item.type === 'folder').sort((a, b) => a.name.localeCompare(b.name));
                        let files = resp.items.filter(item => item.type === 'file').sort((a, b) => a.name.localeCompare(b.name));

                        const renderItem = (item) => {
                            return `<li><input type="checkbox" class="trashCheckbox" value="${item.path}"> <i class="fas fa-${item.type === 'folder' ? 'folder' : 'file'}"></i> ${item.name}
                                                        <button class="btn btn-primary btn-md restoreTrashBtn" data-path="${item.path}" style="margin-left:8px;">Restore</button>
                        <button class="btn btn-danger btn-md deleteTrashBtn" data-path="${item.path}" style="margin-left:4px;">Delete</button>
                            </li>`;
                        };

                        folders.forEach(item => html += renderItem(item));
                        files.forEach(item => html += renderItem(item));
                        html += '</ul>';
                    }
                    $('#trashList').html(html);

                    // Event handlers
                    $('#selectAllTrash').on('click', function() {
                        // Check if all checkboxes are checked
                        var isChecked = $('.trashCheckbox').not(':checked').length === 0;

                        // If all checkboxes are checked, uncheck them, and vice versa
                        if (isChecked) {
                            // Uncheck all checkboxes if they are all checked
                            $('.trashCheckbox').prop('checked', false);
                            $('#selectAllTrash').text('Select All');  // Optionally change button text
                        } else {
                            // Check all checkboxes if they are not all checked
                            $('.trashCheckbox').prop('checked', true);
                            $('#selectAllTrash').text('Deselect All');  // Optionally change button text
                        }
                    });

                    function handleTrashAction(action, paths) {
                        if (paths.length === 0) {
                            showNotification('Please select at least one item.', 'error');
                            return;
                        }

                        const title = action === 'restore' ? 'Restore Selected from Trash' : 'Delete Selected from Trash';
                        const confirmButtonText = action === 'restore' ? '<i class="fas fa-sync-alt"></i> Restore' : '<i class="fas fa-trash"></i> Delete';
                        const confirmButtonColor = action === 'restore' ? '#0073e6' : '#dc3545';

                        Swal.fire({
                            title: title,
                            html: `<div style='text-align:left;'>Are you sure you want to <b>${action}</b> <b>${paths.length}</b> item(s)?</div>`,
                            icon: 'warning',
                            showCancelButton: true,
                            confirmButtonText: confirmButtonText,
                            confirmButtonColor: confirmButtonColor,
                            cancelButtonColor: '#888888',
                            cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                            allowOutsideClick: false,
                            allowEscapeKey: false,
                        }).then((result) => {
                            if (result.isConfirmed) {
                                $.post('?start_trash_action=1', { action: action, items: paths }, function(startResp) {
                                    if (!startResp.sessionId) {
                                        showNotification('Failed to start session', 'error');
                                        return;
                                    }
                                    let sessionId = startResp.sessionId;
                                    let total = startResp.total || paths.length;
                                    let processed = 0;

                                    function processBatch() {
                                        $.post('?process_trash_action=1', { sessionId: sessionId }, function(procResp) {
                                            if (procResp && procResp.busy) { setTimeout(processBatch, 300); return; }
                                            processed += Object.keys(procResp.results || {}).length;
                                            if (procResp.finished) {
                                                showNotification(`Selected items ${action}d!`, 'success');
                                                renderTrash();
                                                Swal.close();
                                            } else {
                                                Swal.update({
                                                    title: `${action.charAt(0).toUpperCase() + action.slice(1)}ing from Trash`,
                                                    html: `<div>Processed ${processed} of ${total}...</div>`,
                                                    showConfirmButton: false,
                                                    allowOutsideClick: false,
                                                    allowEscapeKey: false
                                                });
                                                setTimeout(processBatch, 200);
                                            }
                                        }).fail(function() {
                                            showNotification('Error during batch processing', 'error');
                                        });
                                    }

                                    Swal.fire({
                                        title: `${action.charAt(0).toUpperCase() + action.slice(1)}ing from Trash`,
                                        html: `<div>Processed 0 of ${total}...</div>`,
                                        showConfirmButton: false,
                                        allowOutsideClick: false,
                                        allowEscapeKey: false,
                                        didOpen: () => Swal.showLoading()
                                    });
                                    processBatch();
                                });
                            }
                        });
                    }

                    $('#restoreSelectedTrash').off('click').on('click', function() {
                        let selected = $('.trashCheckbox:checked').map(function() { return $(this).val(); }).get();
                        handleTrashAction('restore', selected);
                    });

                    $('#deleteSelectedTrash').off('click').on('click', function() {
                        let selected = $('.trashCheckbox:checked').map(function() { return $(this).val(); }).get();
                        handleTrashAction('delete', selected);
                    });

                    $('.restoreTrashBtn').off('click').on('click', function() {
                        handleTrashAction('restore', [$(this).data('path')]);
                    });

                    $('.deleteTrashBtn').off('click').on('click', function() {
                        handleTrashAction('delete', [$(this).data('path')]);
                    });
                });
            }
            function restoreTrash(path) {
                Swal.fire({
                    title: 'Restore from Trash',
                    text: `Restore "${path}"?`,
                    icon: 'question',
                    showCancelButton: true,
                    confirmButtonText: 'Restore',
                    confirmButtonColor: '#0073e6',
                    cancelButtonColor: '#ff6b6b',
                    allowOutsideClick: false,
                    allowEscapeKey: false,
                }).then((result) => {
                    if (result.isConfirmed) {
                        $.post('?restore_trash=1', { path: path }, function(resp) {
                            if (resp.success) {
                                showNotification('Item restored from trash!', 'success');
                                renderTrash();
                            } else {
                                showNotification('Failed: ' + (resp.error || 'Unknown error'), 'error');
                            }
                        });
                    }
                });
            }
            function deleteTrash(path) {
                Swal.fire({
                    title: 'Delete from Trash',
                    text: `Delete "${path}" from trash?`,
                    icon: 'warning',
                    showCancelButton: true,
                    confirmButtonText: 'Delete',
                    confirmButtonColor: '#dc3545',
                    allowOutsideClick: false,
                    allowEscapeKey: false,
                }).then((result) => {
                    if (result.isConfirmed) {
                        $.post('?delete_trash=1', { path: path }, function(resp) {
                            if (resp.success) {
                                showNotification('Item deleted from trash!', 'success');
                                renderTrash();
                            } else {
                                showNotification('Failed: ' + (resp.error || 'Unknown error'), 'error');
                            }
                        });
                    }
                });
            }

            // Refresh backups and trash on page load
            renderBackups();
            renderTrash();
            
            // --- NEW FEATURES EVENT HANDLERS ---
            
            // System Health Button
            $('#systemHealthBtn').on('click', function() {
                Swal.fire({
                    title: 'Generating System Health Report',
                    html: 'Please wait...',
                    allowOutsideClick: false,
                    allowEscapeKey: false,
                    didOpen: () => {
                        Swal.showLoading();
                    }
                });
                
                // Use cached system health data if available
                if (dashboardCache.systemHealth && dashboardCache.systemHealth.report) {
                    Swal.close();
                    setTimeout(() => {
                        displaySystemHealthReport(dashboardCache.systemHealth.report);
                    }, 100);
                } else {
                    $.get('?system_health=1', function(response) {
                        Swal.close();
                        dashboardCache.systemHealth = response;
                        if (response.report) {
                            setTimeout(() => {
                                displaySystemHealthReport(response.report);
                            }, 100);
                        } else {
                            showNotification('Failed to generate health report', 'error');
                        }
                    }).fail(function() {
                        Swal.close();
                        showNotification('System health check failed', 'error');
                    });
                }
            });
            
            // Fix Permissions Button
            $('#fixPermissionsBtn').on('click', function() {
                Swal.fire({
                    title: 'Fix WordPress Permissions',
                    text: 'This will fix common permission issues for WordPress files and directories. Continue?',
                    icon: 'question',
                    showCancelButton: true,
                    confirmButtonText: '<i class="fas fa-check"></i> Fix Permissions',
                    cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                    cancelButtonColor: '#ff6b6b',
                }).then((result) => {
                    if (result.isConfirmed) {
                        Swal.fire({
                            title: 'Fixing Permissions',
                            html: 'Please wait...',
                            allowOutsideClick: false,
                            allowEscapeKey: false,
                            didOpen: () => {
                                Swal.showLoading();
                            }
                        });
                        
                        $.post('?fix_wp_permissions=1', function(response) {
                            Swal.close();
                            if (response.message) {
                                showNotification('Permissions fixed successfully', 'success');
                                displayPermissionResults(response.results);
                            } else {
                                showNotification('Failed to fix permissions', 'error');
                            }
                        }).fail(function(xhr) {
                            Swal.close();
                            try {
                                const errorResponse = JSON.parse(xhr.responseText);
                                if (errorResponse.error) {
                                    showNotification(errorResponse.error, 'error');
                                } else {
                                    showNotification('Permission fix failed', 'error');
                                }
                            } catch (e) {
                                showNotification('Permission fix failed', 'error');
                            }
                        });
                    }
                });
            });

            // --- ONE CLICK FIX BUTTON ---
            $('#oneClickFixBtn').on('click', function() {
                oneClickFix();
            });

            
            // --- HELPER FUNCTIONS FOR NEW FEATURES ---
            
            function displaySystemHealthReport(report) {
                let html = `
                    <div style="text-align: left; max-height: 400px; overflow-y: auto;">
                        <h4>System Health Report - ${report.timestamp}</h4>
                        
                        <h5><i class="fas fa-chart-bar"></i> System Information</h5>
                        <ul>
                            <li><strong>PHP Version:</strong> ${report.system.php_version}</li>
                            <li><strong>Server:</strong> ${report.system.server_software}</li>
                            <li><strong>OS:</strong> ${report.system.os}</li>
                            <li><strong>Memory Limit:</strong> ${report.system.memory_limit}</li>
                        </ul>
                        
                        <h5><i class="fas fa-hdd"></i> Disk Space</h5>
                        <ul>
                            <li><strong>Total:</strong> ${report.disk.total_space}</li>
                            <li><strong>Used:</strong> ${report.disk.used_space} (${report.disk.usage_percentage}%)</li>
                            <li><strong>Free:</strong> ${report.disk.free_space}</li>
                            <li><strong>Status:</strong> <span style="color: ${report.disk.status === 'good' ? 'green' : 'orange'}">${report.disk.status}</span></li>
                        </ul>
                        
                        <h5><i class="fas fa-memory"></i> Memory Usage</h5>
                        <ul>
                            <li><strong>Current:</strong> ${report.memory.current_usage}</li>
                            <li><strong>Peak:</strong> ${report.memory.peak_usage}</li>
                            <li><strong>Limit:</strong> ${report.memory.memory_limit}</li>
                            <li><strong>Status:</strong> <span style="color: ${report.memory.status === 'good' ? 'green' : 'orange'}">${report.memory.status}</span></li>
                        </ul>
                        
                        <h5><i class="fas fa-shield-alt"></i> Security Issues</h5>
                        ${report.security.issues.length > 0 ? 
                            `<ul>${report.security.issues.map(issue => `<li style="color: orange;"><i class="fas fa-exclamation-triangle"></i> ${issue}</li>`).join('')}</ul>` :
                            '<p style="color: green;"><i class="fas fa-check-circle"></i> No security issues found</p>'
                        }
                        
                        <h5><i class="fas fa-tachometer-alt"></i> Performance Issues</h5>
                        ${report.performance.issues.length > 0 ? 
                            `<ul>${report.performance.issues.map(issue => `<li style="color: orange;"><i class="fas fa-exclamation-triangle"></i> ${issue}</li>`).join('')}</ul>` :
                            '<p style="color: green;"><i class="fas fa-check-circle"></i> No performance issues found</p>'
                        }
                    </div>
                `;
                
                Swal.fire({
                    title: 'System Health Report',
                    html: html,
                    width: 600,
                    showConfirmButton: true,
                    confirmButtonText: '<i class="fas fa-times"></i> Close',
                    confirmButtonColor: '#ff6b6b',
                });
            }
            
            function displayPermissionResults(results) {
                let html = '<div style="text-align: left;">';
                html += '<h5>Permission Fix Results:</h5><ul>';
                
                for (const [item, result] of Object.entries(results)) {
                    const status = result.status === 'success' ? '<i class="fas fa-check-circle"></i>' : '<i class="fas fa-exclamation-triangle"></i>';
                    const color = result.status === 'success' ? 'green' : 'red';
                    html += `<li style="color: ${color};">${status} ${item}: ${result.message}</li>`;
                }
                
                html += '</ul></div>';
                
                Swal.fire({
                    title: 'Permission Fix Results',
                    html: html,
                    confirmButtonText: '<i class="fas fa-times"></i> Close',
                    confirmButtonColor: '#ff6b6b',
                });
            }
            
            function displaySearchResults(results, count) {
                $('#resultCount').text(count);
                
                if (results.length === 0) {
                    $('#searchResultsList').html('<p>No files found matching your search criteria.</p>');
                } else {
                    let html = '<div class="search-results-list">';
                    results.forEach(file => {
                        const icon = file.type === 'folder' ? '📁' : '📄';
                        const size = file.size ? formatFileSize(file.size) : 'N/A';
                        const date = file.modified ? new Date(file.modified * 1000).toLocaleDateString() : 'N/A';
                        
                        html += `
                            <div class="search-result-item">
                                <span class="search-result-icon">${icon}</span>
                                <span class="search-result-name">${file.name}</span>
                                <span class="search-result-path">${file.path}</span>
                                <span class="search-result-size">${size}</span>
                                <span class="search-result-date">${date}</span>
                            </div>
                        `;
                    });
                    html += '</div>';
                    $('#searchResultsList').html(html);
                }
                
                $('#searchResults').show();
            }
            
            function formatFileSize(bytes) {
                if (bytes === 0) return '0 B';
                const k = 1024;
                const sizes = ['B', 'KB', 'MB', 'GB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }

            // ============================================================
            // MALWARE SCANNER
            // ============================================================

            let lastScanSessionId = null;
            let allScanResults    = {};

            const _sev = {
                critical : { color:'#dc3545', bg:'#fff5f5', border:'#f5c6cb', label:'🔴 Critical' },
                high     : { color:'#fd7e14', bg:'#fff8f0', border:'#ffe0b3', label:'🟠 High'     },
                medium   : { color:'#ffc107', bg:'#fffef0', border:'#ffe066', label:'🟡 Medium'   },
                info     : { color:'#17a2b8', bg:'#f0faff', border:'#b3e5fc', label:'ℹ️ Info'     },
            };
            function sevCfg(s) { return _sev[s] || _sev.info; }

            // ── Launch scan ──────────────────────────────────────────────
            $('#startMalwareScanBtn').on('click', function () {
                Swal.fire({
                    title : '<i class="fas fa-bug"></i> Malware Scanner',
                    html  : `
                        <div style="text-align:left;">
                            <p>Scans every <strong>.php .js .html .htm</strong> file for:</p>
                            <ul>
                                <li>🔴 <strong>sawab-ltd.com</strong> injection (kgb2tKK / T6Lv6St / MreFnKR)</li>
                                <li>🔴 PHP <code>eval(base64_decode(…))</code> obfuscation</li>
                                <li>🔴 Webshell signatures (WSO, FilesMan)</li>
                                <li>🔴 Remote-code-execution patterns</li>
                                <li>🟠 LiteSpeed script-tag injection</li>
                                <li>🟠 Large base64 payloads</li>
                            </ul>
                            <p class="c-grey" style="font-size:0.85rem;">Files &gt; 5 MB are skipped. Large installs may take a minute.</p>
                        </div>`,
                    icon              : 'question',
                    showCancelButton  : true,
                    confirmButtonText : '<i class="fas fa-play"></i> Start Scan',
                    cancelButtonText  : '<i class="fas fa-times"></i> Cancel',
                    confirmButtonColor: '#dc3545',
                    cancelButtonColor : '#6c757d',
                    allowOutsideClick : false,
                    allowEscapeKey    : false,
                }).then(r => { if (r.isConfirmed) startMalwareScan(); });
            });

            function startMalwareScan() {
                allScanResults    = {};
                lastScanSessionId = null;

                $.post('?start_scan=1', {
                    scanRootDir: $('#scanRootDir').val().trim(),
                    scanExcludePaths: $('#scanExcludePaths').val(),
                }, function (resp) {
                    if (resp.error) { showNotification(resp.error, 'error'); return; }

                    lastScanSessionId = resp.sessionId;
                    const total = resp.total;
                    let scanned = 0, infected = 0;

                    Swal.fire({
                        title         : '<i class="fas fa-search"></i> Scanning…',
                        html          : scanProgressHtml(0, total, 0),
                        allowOutsideClick: false,
                        allowEscapeKey   : false,
                        showConfirmButton: false,
                        didOpen: () => Swal.showLoading(),
                    });

                    function batch() {
                        $.post('?process_scan=1', { sessionId: lastScanSessionId }, function (r) {
                            if (r && r.busy) { setTimeout(batch, 300); return; }
                            scanned  = r.scanned_count;
                            infected = r.infected_count;
                            if (r.batch_results) Object.assign(allScanResults, r.batch_results);
                            Swal.update({ html: scanProgressHtml(scanned, total, infected) });
                            if (r.finished) { Swal.close(); showScanResults(allScanResults, scanned, infected); }
                            else setTimeout(batch, 100);
                        }).fail(() => { Swal.close(); showNotification('Scan failed mid-way', 'error'); });
                    }
                    batch();
                }).fail(() => showNotification('Could not start scan', 'error'));
            }

            function scanProgressHtml(scanned, total, infected) {
                const pct = total > 0 ? Math.round(scanned / total * 100) : 0;
                return `
                    <div style="text-align:center;">
                        <div style="width:100%;background:#e9ecef;border-radius:10px;height:12px;overflow:hidden;margin:10px 0 6px;">
                            <div style="width:${pct}%;background:linear-gradient(90deg,#667eea,#764ba2);height:100%;border-radius:10px;transition:width .3s;"></div>
                        </div>
                        <div style="font-size:.85rem;color:#666;">${pct}% — ${scanned} of ${total} files scanned</div>
                        <div style="margin-top:10px;font-size:1.05rem;color:${infected>0?'#dc3545':'#28a745'};">
                            ${infected > 0 ? `⚠️ ${infected} infected file(s) found so far` : '✅ No infections found yet'}
                        </div>
                    </div>`;
            }

            // ── Display results ──────────────────────────────────────────
            function showScanResults(results, totalScanned, infectedCount) {
                const $div = $('#malwareScanResults');

                if (infectedCount === 0) {
                    $div.html(`
                        <div style="padding:20px;background:#d4edda;border:1px solid #c3e6cb;border-radius:8px;text-align:center;">
                            <div style="font-size:2rem;">✅</div>
                            <strong style="color:#155724;">No malware found</strong>
                            <div class="c-grey">${totalScanned} files scanned — all clean</div>
                        </div>`);
                    return;
                }

                let html = `
                    <div style="padding:12px;background:#fff3cd;border:1px solid #ffc107;border-radius:8px;margin-bottom:12px;">
                        <strong>⚠️ ${infectedCount} infected file(s)</strong> found in ${totalScanned} scanned.
                    </div>
                    <div style="margin-bottom:10px;display:flex;gap:8px;flex-wrap:wrap;">
                        <button class="btn btn-secondary btn-md" id="selectAllMalwareBtn">Select All</button>
                        <button class="btn btn-info btn-md" id="saveMalwarePresetBtn">
                            <i class="fas fa-save"></i> Save as Preset
                        </button>
                        <button class="btn btn-warning  btn-md" id="quarantineSelBtn">
                            <i class="fas fa-shield-virus"></i> Quarantine Selected
                        </button>
                        <button class="btn btn-danger   btn-md" id="deleteSelMalwareBtn">
                            <i class="fas fa-trash"></i> Delete Selected
                        </button>
                    </div>
                    <div id="malwareFileList">`;

                for (const [absPath, fd] of Object.entries(results)) {
                    const rel     = fd.relative_path || absPath;
                    const matches = fd.matches || [];
                    const topSev  = matches.some(m => m.severity === 'critical') ? 'critical'
                                  : matches.some(m => m.severity === 'high')     ? 'high' : 'medium';
                    const cfg     = sevCfg(topSev);
                    const itemId  = 'mi_' + btoa(unescape(encodeURIComponent(absPath))).replace(/[^a-z0-9]/gi,'');

                    let matchLines = '';
                    matches.forEach(m => {
                        const mc = sevCfg(m.severity);
                        matchLines += `
                            <div style="margin:4px 0;padding:5px 8px;background:#f8f9fa;border-left:3px solid ${mc.color};border-radius:3px;font-size:.8rem;">
                                <span style="color:${mc.color};font-weight:600;">${mc.label}</span>
                                &nbsp;Line&nbsp;${m.line_number}: <em>${escapeHtml(m.description)}</em>
                                ${m.line_preview ? `<div style="font-family:monospace;color:#666;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(m.line_preview)}">${escapeHtml(m.line_preview)}</div>` : ''}
                            </div>`;
                    });

                    html += `
                        <div class="malware-result-item" data-abspath="${escapeHtml(absPath)}"
                             style="margin-bottom:10px;padding:12px;background:${cfg.bg};border:1px solid ${cfg.border};border-radius:8px;">
                            <div style="display:flex;align-items:flex-start;gap:10px;">
                                <input type="checkbox" class="malwareChk" id="${itemId}"
                                       value="${escapeHtml(absPath)}" style="margin-top:3px;width:16px;height:16px;flex-shrink:0;">
                                <div style="flex:1;min-width:0;">
                                    <label for="${itemId}" style="cursor:pointer;font-weight:600;color:${cfg.color};word-break:break-all;">${escapeHtml(rel)}</label>
                                    <div style="margin-top:6px;">${matchLines}</div>
                                </div>
                            </div>
                        </div>`;
                }

                html += '</div>';
                $div.html(html);
                $('html,body').animate({ scrollTop: $div.offset().top - 20 }, 400);

                // ── Button handlers ───────────────────────────────────────
                $('#selectAllMalwareBtn').on('click', function () {
                    const allOn = $('.malwareChk:not(:checked)').length === 0;
                    $('.malwareChk').prop('checked', !allOn);
                    $(this).text(allOn ? 'Select All' : 'Deselect All');
                });

                $('#saveMalwarePresetBtn').on('click', function () {
                    const sel = $('.malwareChk:checked').map(function () { return $(this).val(); }).get();
                    if (!sel.length) { showNotification('Select at least one file to save', 'error'); return; }
                    Swal.fire({
                        title: 'Save as Preset',
                        input: 'text',
                        inputLabel: 'Preset name (e.g., malware-infected)',
                        inputPlaceholder: 'Enter preset name...',
                        showCancelButton: true,
                        confirmButtonText: '<i class="fas fa-save"></i> Save',
                        cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                        confirmButtonColor: '#0dcaf0',
                        cancelButtonColor: '#6c757d',
                        allowOutsideClick: false,
                    }).then(r => {
                        if (!r.isConfirmed || !r.value.trim()) return;
                        const presetName = r.value.trim().replace(/[^a-zA-Z0-9_-]/g, '_');
                        const presetData = JSON.stringify({ folders: [], files: sel });
                        $.post('?save_preset=1', { name: presetName, data: presetData }, function(resp) {
                            if (resp.success) {
                                showNotification(`Preset "${presetName}" saved with ${sel.length} file(s)!`, 'success');
                                // Auto-load the preset to populate the file list
                                $.post('?load_preset=' + encodeURIComponent(presetName), function(loadResp) {
                                    if (loadResp.folders) {
                                        folders = loadResp.folders || [];
                                        files = loadResp.files || [];
                                        updateFolderList();
                                        updateFileList();
                                        updateDeleteSectionVisibility();
                                    }
                                }, 'json').fail(() => {});
                            } else {
                                showNotification(resp.error || 'Failed to save preset', 'error');
                            }
                        });
                    });
                });

                $('#quarantineSelBtn').on('click', function () {
                    const sel = $('.malwareChk:checked').map(function () { return $(this).val(); }).get();
                    if (!sel.length) { showNotification('Select at least one file', 'error'); return; }
                    actOnMalware(sel, 'quarantine');
                });

                $('#deleteSelMalwareBtn').on('click', function () {
                    const sel = $('.malwareChk:checked').map(function () { return $(this).val(); }).get();
                    if (!sel.length) { showNotification('Select at least one file', 'error'); return; }
                    actOnMalware(sel, 'delete');
                });
            }

            // ── Quarantine / delete confirmed files ─────────────────────
            function actOnMalware(filePaths, action) {
                const label   = action === 'quarantine' ? 'Quarantine' : 'Delete';
                const btnClr  = action === 'quarantine' ? '#fd7e14' : '#dc3545';
                const warning = action === 'delete'
                    ? '<strong style="color:#dc3545;">⚠️ Deleted files cannot be recovered.</strong><br>'
                    : 'Files will be moved to <strong>quarantine/</strong> and can be restored later.<br>';

                Swal.fire({
                    title             : `${label} ${filePaths.length} File(s)?`,
                    html              : `<div style="text-align:left;">${warning}
                        <ul style="max-height:160px;overflow-y:auto;margin-top:8px;font-size:.85rem;">
                            ${filePaths.map(f => `<li style="word-break:break-all;">${escapeHtml(f)}</li>`).join('')}
                        </ul></div>`,
                    icon              : 'warning',
                    showCancelButton  : true,
                    confirmButtonText : `<i class="fas fa-${action==='quarantine'?'shield-virus':'trash'}"></i> ${label}`,
                    cancelButtonText  : '<i class="fas fa-times"></i> Cancel',
                    confirmButtonColor: btnClr,
                    cancelButtonColor : '#6c757d',
                    allowOutsideClick : false,
                    allowEscapeKey    : false,
                }).then(r => {
                    if (!r.isConfirmed) return;

                    Swal.fire({
                        title: `${label}ing…`, html: 'Please wait…',
                        allowOutsideClick: false, allowEscapeKey: false,
                        didOpen: () => Swal.showLoading(),
                    });

                    $.post('?act_on_malware=1', {
                        files    : filePaths,
                        action   : action,
                        sessionId: lastScanSessionId || '',
                    }, function (resp) {
                        Swal.close();
                        let ok = 0, fail = 0;

                        for (const [path, res] of Object.entries(resp.results || {})) {
                            if (res.status === 'quarantined' || res.status === 'deleted') {
                                ok++;
                                // Remove the card from the UI
                                $(`.malware-result-item[data-abspath="${escapeHtml(path)}"]`).fadeOut(350, function () { $(this).remove(); });
                                delete allScanResults[path];
                            } else {
                                fail++;
                                console.warn('Act on malware failed for', path, res);
                            }
                        }

                        if (fail === 0) showNotification(`${ok} file(s) ${action === 'quarantine' ? 'quarantined' : 'deleted'}!`, 'success');
                        else showNotification(`${ok} succeeded, ${fail} failed — check permissions.`, 'error');
                    }).fail(() => { Swal.close(); showNotification(`Failed to ${action} files`, 'error'); });
                });
            }

            // ── Quarantine viewer ────────────────────────────────────────
            $('#listQuarantineBtn').on('click', openQuarantineViewer);

            function openQuarantineViewer() {
                Swal.fire({
                    title             : '<i class="fas fa-shield-virus"></i> Quarantine',
                    html              : '<div class="text-center"><i class="fas fa-spinner fa-spin"></i> Loading…</div>',
                    confirmButtonText : '<i class="fas fa-times"></i> Close',
                    confirmButtonColor: '#6c757d',
                    width             : 700,
                    allowOutsideClick : false,
                    allowEscapeKey    : false,
                    didOpen() {
                        $.get('?list_quarantine=1', function (resp) {
                            if (!resp.items || resp.items.length === 0) {
                                Swal.update({ html: '<div style="text-align:center;padding:20px;color:#666;">Quarantine is empty.</div>' });
                                return;
                            }

                            let html = `<div style="margin-bottom:8px;font-size:.9rem;color:#666;">${resp.count} file(s) in quarantine</div>
                                <ul style="list-style:none;padding:0;max-height:320px;overflow-y:auto;">`;

                            resp.items.forEach(item => {
                                html += `
                                    <li style="padding:8px;border-bottom:1px solid #eee;display:flex;align-items:center;gap:10px;">
                                        <span style="flex:1;word-break:break-all;font-size:.83rem;">📄 ${escapeHtml(item.name)}</span>
                                        <button class="btn btn-sm btn-warning qRestoreBtn" data-name="${escapeHtml(item.name)}">
                                            <i class="fas fa-undo"></i> Restore
                                        </button>
                                    </li>`;
                            });

                            html += `</ul>
                                <div style="margin-top:10px;text-align:right;">
                                    <button class="btn btn-danger btn-md" id="qEmptyAllBtn">
                                        <i class="fas fa-broom"></i> Empty All
                                    </button>
                                </div>`;

                            Swal.update({ html });

                            $('.qRestoreBtn').off('click').on('click', function () {
                                const name = $(this).data('name');
                                $.post('?restore_quarantine=1', { name }, function (r) {
                                    if (r.success) { showNotification('File restored!', 'success'); openQuarantineViewer(); }
                                    else showNotification(r.error || 'Restore failed', 'error');
                                });
                            });

                            $('#qEmptyAllBtn').off('click').on('click', doEmptyQuarantine);
                        });
                    },
                });
            }

            // ── Empty quarantine ─────────────────────────────────────────
            $('#emptyQuarantineBtn').on('click', doEmptyQuarantine);

            function doEmptyQuarantine() {
                Swal.fire({
                    title             : 'Empty Quarantine?',
                    text              : 'All quarantined files will be permanently deleted. This cannot be undone.',
                    icon              : 'warning',
                    showCancelButton  : true,
                    confirmButtonText : '<i class="fas fa-broom"></i> Empty All',
                    cancelButtonText  : '<i class="fas fa-times"></i> Cancel',
                    confirmButtonColor: '#dc3545',
                    cancelButtonColor : '#6c757d',
                    allowOutsideClick : false,
                    allowEscapeKey    : false,
                }).then(r => {
                    if (!r.isConfirmed) return;
                    $.post('?empty_quarantine=1', function (resp) {
                        if (resp.success) {
                            showNotification(`Quarantine emptied — ${resp.deleted} file(s) deleted`, 'success');
                            Swal.close();
                        } else showNotification('Failed to empty quarantine', 'error');
                    });
                });
            }

            // ============================================================
            // DATABASE CLEANER
            // ============================================================

            const dbCategories = {
                transients:       { label: 'Transients (_transient_*)',      icon: 'fa-clock',       singular: 'transient', plural: 'transients' },
                site_transients:  { label: 'Site Transients (_site_transient_*)', icon: 'fa-clock', singular: 'site transient', plural: 'site transients' },
                revisions:        { label: 'Post Revisions',                icon: 'fa-copy',        singular: 'revision', plural: 'revisions' },
                spam_comments:    { label: 'Spam Comments',                 icon: 'fa-comment-slash', singular: 'spam comment', plural: 'spam comments' },
                trashed_comments: { label: 'Trashed Comments',              icon: 'fa-trash',       singular: 'trashed comment', plural: 'trashed comments' },
                orphaned_postmeta:    { label: 'Orphaned Post Meta',        icon: 'fa-puzzle-piece', singular: 'orphaned post meta', plural: 'orphaned post metas' },
                orphaned_commentmeta: { label: 'Orphaned Comment Meta',     icon: 'fa-puzzle-piece', singular: 'orphaned comment meta', plural: 'orphaned comment metas' },
                autoload_options: { label: 'Autoload Options',              icon: 'fa-cog',         singular: 'autoload option', plural: 'autoload options' },
                trashed_posts:    { label: 'Trashed Posts',                 icon: 'fa-trash',       singular: 'trashed post', plural: 'trashed posts' },
                malware_posts:    { label: '⚠️ Malware in Posts',           icon: 'fa-bug',         singular: 'infected post', plural: 'infected posts' },
                malware_comments: { label: '⚠️ Malware in Comments',        icon: 'fa-bug',         singular: 'infected comment', plural: 'infected comments' },
                malware_options:  { label: '⚠️ Malware in Options',         icon: 'fa-bug',         singular: 'infected option', plural: 'infected options' },
            };

            let dbScanCounts  = {};
            let dbCurrentPage = {};

            // ── Scan database ──────────────────────────────────────────
            $('#dbScanBtn').on('click', function () {
                Swal.fire({
                    title: '<i class="fas fa-database"></i> Scanning Database...',
                    html: 'Analyzing database for cleanable items...',
                    allowOutsideClick: false, allowEscapeKey: false,
                    didOpen: () => Swal.showLoading(),
                });
                $.get('?db_scan=1', function (resp) {
                    Swal.close();
                    if (resp.error) { showNotification(resp.error, 'error'); return; }
                    dbScanCounts = resp.counts;
                    dbCurrentPage = {};
                    for (const cat in dbCategories) dbCurrentPage[cat] = 1;
                    showDbSummary(dbScanCounts);
                }).fail(() => { showNotification('Scan failed', 'error'); Swal.close(); });
            });

            function showDbSummary(counts) {
                const total = Object.values(counts).reduce((s, v) => s + v, 0);
                if (total === 0) {
                    $('#dbScanSummary').html('<div style="padding:16px;background:#d4edda;border:1px solid #c3e6cb;border-radius:8px;text-align:center;"><strong style="color:#155724;">✅ Database is clean!</strong><br>No items found to clean.</div>');
                    $('#dbCategoryTabs').hide();
                    return;
                }
                let html = `<div style="padding:12px;background:#e7f3ff;border:1px solid #b3d9ff;border-radius:8px;margin-bottom:12px;"><strong>📊 Found ${total} cleanable items</strong> across ${Object.keys(counts).filter(k => counts[k] > 0).length} categories.</div>`;
                html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px;">';
                for (const [cat, count] of Object.entries(counts)) {
                    if (count === 0) continue;
                    const info = dbCategories[cat];
                    html += `<div style="padding:12px;background:#f8f9fa;border:1px solid #dee2e6;border-radius:8px;cursor:pointer;" onclick="openDbCategory('${cat}')">
                        <div style="font-weight:600;color:#495057;"><i class="fas ${info.icon}"></i> ${info.label}</div>
                        <div style="font-size:1.5rem;font-weight:700;color:#007bff;margin:6px 0;">${count.toLocaleString()}</div>
                        <div style="font-size:.75rem;color:#6c757d;">click to review &amp; clean</div>
                    </div>`;
                }
                html += '</div>';
                $('#dbScanSummary').html(html);
                $('#dbCategoryTabs').show();
            }

            window.openDbCategory = function (category) {
                const info = dbCategories[category];
                if (!info) return;
                const tabId = `db-tab-${category}`;
                const paneId = `db-pane-${category}`;

                // Add tab if not exists
                if ($(`.nav-tabs #${tabId}`).length === 0) {
                    const count = dbScanCounts[category] || 0;
                    $(`#${tabId}-nav, .nav-tabs`).append(`<li class="nav-item" role="presentation"><button class="nav-link" id="${tabId}" data-bs-toggle="tab" data-bs-target="#${paneId}" type="button" role="tab">${info.label} (${count.toLocaleString()})</button></li>`);
                    $(`#${paneId}-content, .tab-content`).append(`<div class="tab-pane fade" id="${paneId}" role="tabpanel"><div id="dbList-${category}" class="mt-2"><i class="fas fa-spinner fa-spin"></i> Loading...</div><div id="dbActions-${category}" class="mt-2 d-flex gap-2 flex-wrap" style="display:none!important;"></div></div>`);
                }

                // Activate tab
                const tabEl = document.getElementById(tabId);
                if (tabEl) { new bootstrap.Tab(tabEl).show(); }

                // Load list
                loadDbList(category);
            }

            window.loadDbList = function (category, page) {
                page = page || 1;
                dbCurrentPage[category] = page;
                const $list = $(`#dbList-${category}`);
                if (!$list.length) return;
                $list.html('<i class="fas fa-spinner fa-spin"></i> Loading...');

                $.get('?db_get_list=1&category=' + encodeURIComponent(category) + '&page=' + page, function (resp) {
                    if (resp.error) { $list.html('<div class="alert alert-danger">' + resp.error + '</div>'); return; }
                    const items = resp.items || [];
                    const total = resp.total || 0;
                    if (items.length === 0) {
                        $list.html('<div class="alert alert-info">No items in this category.</div>');
                        return;
                    }
                    let html = `<div style="margin-bottom:8px;display:flex;gap:8px;flex-wrap:wrap;">
                        <button class="btn btn-sm btn-outline-secondary" onclick="selectAllDbItems('${category}', true)">Select All</button>
                        <button class="btn btn-sm btn-outline-secondary" onclick="selectAllDbItems('${category}', false)">Deselect All</button>
                        <button class="btn btn-sm btn-danger" onclick="cleanSelectedDbItems('${category}')">
                            <i class="fas fa-trash"></i> Clean Selected
                        </button>
                        <button class="btn btn-sm btn-warning" onclick="cleanAllDbItems('${category}')">
                            <i class="fas fa-broom"></i> Clean All ${dbCategories[category]?.plural || category}
                        </button>
                    </div>`;
                    html += `<div style="font-size:.85rem;color:#666;margin-bottom:8px;">Showing ${items.length} of ${total.toLocaleString()} items (Page ${page})</div>`;
                    html += '<div class="list-group">';
                    items.forEach(item => {
                        const sizeStr = item.size_bytes ? ` · ${formatBytes(item.size_bytes)}` : '';
                        const statusStr = item.status ? ` <span class="badge bg-${item.status === 'EXPIRED' ? 'danger' : 'secondary'}">${item.status}</span>` : '';
                        const autoloadStr = item.autoload ? ` <span class="badge bg-info">autoload: ${item.autoload}</span>` : '';
                        const isMalware = ['malware_posts','malware_comments','malware_options'].includes(category);
                        const previewId = `preview-${category}-${item.id}`;

                        // "View Full Content" toggle is only meaningful for malware
                        // categories (the server only fills full_content there). For
                        // normal DB tables we instead show the row detail inline.
                        let detailHtml = '';
                        if (isMalware && item.full_content) {
                            detailHtml = `
                                    <button class="btn btn-sm btn-outline-secondary mt-1" onclick="togglePreview('${previewId}', this)" id="btn-${previewId}">
                                        <i class="fas fa-eye"></i> View Full Content
                                    </button>
                                    <div id="${previewId}" style="display:none;margin-top:6px;">
                                        ${item.full_content}
                                    </div>`;
                        } else if (item.preview) {
                            detailHtml = `<div style="font-size:.8rem;color:#555;margin-top:4px;word-break:break-word;">${item.preview}</div>`;
                        }

                        html += `<div class="list-group-item">
                            <div class="d-flex align-items-start gap-2">
                                <input type="checkbox" class="dbChk" data-category="${category}" data-id="${escapeHtml(String(item.id))}" value="${escapeHtml(String(item.id))}" style="width:16px;height:16px;margin-top:4px;flex-shrink:0;">
                                <div style="flex:1;min-width:0;">
                                    <div style="font-weight:600;word-break:break-all;">${escapeHtml(item.name)}${statusStr}${autoloadStr}${sizeStr}</div>
                                    ${item.date ? `<div style="font-size:.75rem;color:#999;margin-top:2px;">${escapeHtml(item.date)}</div>` : ''}
                                    ${item.type ? `<div style="font-size:.75rem;color:#999;">Type: ${escapeHtml(item.type)}</div>` : ''}
                                    ${item.extra ? `<div>${item.extra}</div>` : ''}
                                    ${detailHtml}
                                </div>
                            </div>
                        </div>`;
                    });
                    html += '</div>';

                    // Pagination
                    const totalPages = Math.ceil(total / 50);
                    if (totalPages > 1) {
                        html += '<div class="d-flex justify-content-center gap-1 mt-3 flex-wrap">';
                        if (page > 1) html += `<button class="btn btn-sm btn-outline-primary" onclick="loadDbList('${category}', ${page - 1})">← Prev</button>`;
                        for (let p = 1; p <= totalPages; p++) {
                            if (p === 1 || p === totalPages || (p >= page - 2 && p <= page + 2)) {
                                html += `<button class="btn btn-sm ${p === page ? 'btn-primary' : 'btn-outline-primary'}" onclick="loadDbList('${category}', ${p})">${p}</button>`;
                            } else if (p === page - 3 || p === page + 3) {
                                html += '<span>...</span>';
                            }
                        }
                        if (page < totalPages) html += `<button class="btn btn-sm btn-outline-primary" onclick="loadDbList('${category}', ${page + 1})">Next →</button>`;
                        html += '</div>';
                    }
                    $list.html(html);
                }).fail(() => { $list.html('<div class="alert alert-danger">Failed to load items.</div>'); });
            }

            window.selectAllDbItems = function (category, select) {
                $(`#dbList-${category} .dbChk`).prop('checked', select);
            };

            window.togglePreview = function(id, btn) {
                const $box = $('#' + id);
                const isVisible = $box.is(':visible');
                if (isVisible) {
                    $box.slideUp(200);
                    $(btn).html('<i class="fas fa-eye"></i> View Full Content');
                } else {
                    $box.slideDown(200);
                    $(btn).html('<i class="fas fa-eye-slash"></i> Hide Content');
                }
            };

            window.cleanSelectedDbItems = function (category) {
                const $checks = $(`#dbList-${category} .dbChk:checked`);
                if ($checks.length === 0) { showNotification('Select at least one item', 'error'); return; }
                const ids = $checks.map(function () { return $(this).val(); }).get();
                Swal.fire({
                    title: `Clean ${ids.length} ${dbCategories[category]?.singular || 'item'}(s)?`,
                    html: `<div class="text-start">This will permanently remove selected items. This cannot be undone.</div>`,
                    icon: 'warning', showCancelButton: true,
                    confirmButtonText: `<i class="fas fa-trash"></i> Clean ${ids.length} Items`,
                    cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                    confirmButtonColor: '#dc3545', cancelButtonColor: '#6c757d',
                    allowOutsideClick: false, allowEscapeKey: false,
                }).then(r => {
                    if (!r.isConfirmed) return;
                    Swal.fire({ title: 'Cleaning...', html: 'Please wait…', allowOutsideClick: false, allowEscapeKey: false, didOpen: () => Swal.showLoading() });
                    $.post('?db_clean_items=1', { category, ids }, function (resp) {
                        Swal.close();
                        if (resp.error) { showNotification(resp.error, 'error'); return; }
                        showNotification(`Cleaned ${resp.deleted || 0} items!`, 'success');
                        // Refresh summary
                        $.get('?db_scan=1', function (sresp) {
                            if (!sresp.error) { dbScanCounts = sresp.counts; showDbSummary(dbScanCounts); }
                        });
                    }).fail(() => { Swal.close(); showNotification('Clean failed', 'error'); });
                });
            };

            window.cleanAllDbItems = function (category) {
                const count = dbScanCounts[category] || 0;
                if (count === 0) { showNotification('No items to clean in this category.', 'info'); return; }
                Swal.fire({
                    title: `Clean ALL ${count.toLocaleString()} ${dbCategories[category]?.plural || category}?`,
                    html: `<div class="text-start"><strong style="color:#dc3545;">⚠️ This action is permanent and cannot be undone.</strong></div>`,
                    icon: 'warning', showCancelButton: true,
                    confirmButtonText: `<i class="fas fa-broom"></i> Clean All ${count.toLocaleString()}`,
                    cancelButtonText: '<i class="fas fa-times"></i> Cancel',
                    confirmButtonColor: '#dc3545', cancelButtonColor: '#6c757d',
                    allowOutsideClick: false, allowEscapeKey: false,
                }).then(r => {
                    if (!r.isConfirmed) return;
                    Swal.fire({ title: 'Cleaning...', html: 'Please wait…', allowOutsideClick: false, allowEscapeKey: false, didOpen: () => Swal.showLoading() });
                    $.post('?db_clean_all=1', { category }, function (resp) {
                        Swal.close();
                        if (resp.error) { showNotification(resp.error, 'error'); return; }
                        const isMalware = category.startsWith('malware_');
                        if (isMalware) {
                            // For malware: show success and clear the list
                            showNotification(`All ${count} items removed!`, 'success');
                            $(`#dbList-${category}`).html(`
                                <div style="padding:20px;background:#d4edda;border:1px solid #c3e6cb;border-radius:8px;text-align:center;">
                                    <div style="font-size:2rem;">✅</div>
                                    <strong style="color:#155724;">All ${dbCategories[category]?.plural || category} cleaned!</strong>
                                    <div class="c-grey mt-2">${count} items removed successfully.</div>
                                </div>`);
                            $(`#dbActions-${category}`).hide();
                            // Refresh summary
                            $.get('?db_scan=1', function (sresp) {
                                if (!sresp.error) { dbScanCounts = sresp.counts; showDbSummary(dbScanCounts); }
                            });
                        } else {
                            showNotification(`Cleaned ${resp.deleted || 0} items!`, 'success');
                            $.get('?db_scan=1', function (sresp) {
                                if (!sresp.error) { dbScanCounts = sresp.counts; showDbSummary(dbScanCounts); }
                            });
                        }
                    }).fail(() => { showNotification('Clean all failed', 'error'); });
                });
            };

            function formatBytes(bytes) {
                if (bytes === 0) return '0 B';
                const k = 1024;
                const sizes = ['B', 'KB', 'MB', 'GB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }
        });
    </script>

    <!-- ============================================================
         COMMAND EXECUTOR SCRIPT
         ============================================================ -->
    <script>
        $(document).on('click', '#runCmdBtn', function () {
            const cmd = $('#cmdInput').val().trim();
            if (!cmd) { showNotification('Enter a command to run', 'error'); return; }
            $('#cmdOutput').show();
            $('#cmdExecuted').text('Running: ' + cmd);
            $('#cmdOutputBox').html('<i class="fas fa-spinner fa-spin"></i> Executing...');
            $.post('?exec_cmd=1', { cmd: cmd }, function (resp) {
                if (resp.error) {
                    $('#cmdOutputBox').html(formatCmdError(resp.error));
                    return;
                }
                $('#cmdOutputBox').text(resp.output);
            }).fail(function (xhr) {
                // The server sends its "command blocked / disabled functions"
                // guidance as a JSON body with a 4xx status, so read it from the
                // response instead of showing a generic "Request failed".
                var msg = 'Request failed';
                try {
                    var body = xhr.responseJSON || JSON.parse(xhr.responseText || '{}');
                    if (body && body.error) msg = body.error;
                    else if (xhr.responseText) msg = xhr.responseText;
                } catch (e) {
                    if (xhr && xhr.responseText) msg = xhr.responseText;
                }
                $('#cmdOutputBox').html(formatCmdError(msg));
            });
        });

        // Render a command error/guidance message as readable, multi-line HTML.
        function formatCmdError(message) {
            var text = String(message)
                .replace(/\\n/g, '\n')   // literal "\n" from the server -> real newline
                .replace(/\\\\/g, '\\'); // collapse escaped backslashes
            var div = document.createElement('div');
            div.textContent = text;      // safely HTML-escape the content
            return '<span style="color:#f8d7da; white-space:pre-wrap; '
                 + 'display:block; text-align:left;">' + div.innerHTML + '</span>';
        }

        $(document).on('click', '.cmd-preset', function () {
            $('#cmdInput').val($(this).data('cmd'));
        });

        $(document).on('click', '#copyCmdOutput', function () {
            const text = $('#cmdOutputBox').text();
            navigator.clipboard.writeText(text).then(() => {
                showNotification('Output copied to clipboard', 'success');
            }).catch(() => {
                // Fallback
                const ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
                showNotification('Output copied', 'success');
            });
        });

        $('#cmdInput').on('keydown', function (e) {
            if (e.key === 'Enter') { $('#runCmdBtn').click(); }
        });
    </script>

    <!-- ============================================================
         ADVANCED WP TOOLKIT SCRIPT (search-replace, users, export, integrity)
         ============================================================ -->
    <script>
        // ---------- DATABASE SEARCH-REPLACE ----------
        $(document).on('click', '#srRunBtn', function () {
            const search = $('#srSearch').val();
            const replace = $('#srReplace').val();
            const dryRun = $('#srDryRun').is(':checked');
            if (!search) { showNotification('Enter the text to search for', 'error'); return; }

            const doRun = () => {
                $('#srResults').html('<i class="fas fa-spinner fa-spin"></i> Starting...');
                $.post('?sr_start=1', { search, replace, dryrun: dryRun ? 1 : 0 }, function (start) {
                    if (start.error) { $('#srResults').html('<div class="alert alert-danger">' + start.error + '</div>'); return; }
                    const total = start.total;
                    const sessionId = start.sessionId;
                    function step() {
                        $.post('?sr_process=1', { sessionId }, function (r) {
                            if (r && r.busy) { setTimeout(step, 300); return; }
                            if (r.error) { $('#srResults').html('<div class="alert alert-danger">' + r.error + '</div>'); return; }
                            const pct = Math.round((r.progress || 0) * 100);
                            $('#srResults').html('<div>Processing tables... ' + pct + '%</div>');
                            if (r.finished) {
                                const mode = r.dryrun ? 'Dry run' : 'Applied';
                                $('#srResults').html(
                                    '<div class="alert alert-' + (r.dryrun ? 'info' : 'success') + '">'
                                    + '<strong>' + mode + ' complete.</strong><br>'
                                    + 'Rows changed: ' + r.rows_changed + '<br>'
                                    + 'Cells changed: ' + r.cells_changed
                                    + (r.dryrun ? '<br><em>Re-run with Dry Run unchecked to apply.</em>' : '')
                                    + '</div>');
                                showNotification(mode + ' complete', 'success');
                            } else {
                                setTimeout(step, 100);
                            }
                        }).fail(() => $('#srResults').html('<div class="alert alert-danger">Request failed</div>'));
                    }
                    step();
                }).fail(() => $('#srResults').html('<div class="alert alert-danger">Could not start</div>'));
            };

            if (!dryRun) {
                Swal.fire({
                    title: 'Apply changes to the database?',
                    html: 'This will <strong>modify</strong> your database directly.<br>Make sure you have a backup.',
                    icon: 'warning', showCancelButton: true, confirmButtonText: 'Yes, apply',
                    confirmButtonColor: '#d33'
                }).then(res => { if (res.isConfirmed) doRun(); });
            } else {
                doRun();
            }
        });

        // ---------- ADMIN USER MANAGER ----------
        $(document).on('click', '#wpListAdminsBtn', function () {
            $('#wpAdminsList').html('<i class="fas fa-spinner fa-spin"></i> Loading...');
            $.get('?wp_list_admins=1', function (r) {
                if (r.error) { $('#wpAdminsList').html('<div class="alert alert-danger">' + r.error + '</div>'); return; }
                const admins = r.admins || [];
                if (!admins.length) { $('#wpAdminsList').html('<div class="alert alert-info">No administrators found.</div>'); return; }
                let html = '<div class="list-group">';
                admins.forEach(a => {
                    html += '<div class="list-group-item d-flex justify-content-between align-items-center flex-wrap gap-2">'
                        + '<div><strong>' + escapeHtml(a.login) + '</strong> '
                        + '<span class="badge bg-secondary">ID ' + a.id + '</span><br>'
                        + '<small class="text-muted">' + escapeHtml(a.email) + ' · ' + escapeHtml(a.registered) + '</small></div>'
                        + '<button class="btn btn-sm btn-warning wpResetPwBtn" data-id="' + a.id + '" data-login="' + escapeHtml(a.login) + '">'
                        + '<i class="fas fa-key"></i> Reset Password</button></div>';
                });
                html += '</div>';
                $('#wpAdminsList').html(html);
            }).fail(() => $('#wpAdminsList').html('<div class="alert alert-danger">Failed to load admins</div>'));
        });

        $(document).on('click', '.wpResetPwBtn', function () {
            const id = $(this).data('id');
            const login = $(this).data('login');
            Swal.fire({
                title: 'Reset password for ' + login,
                input: 'password',
                inputPlaceholder: 'New password (min 6 chars)',
                inputAttributes: { minlength: 6 },
                showCancelButton: true, confirmButtonText: 'Reset',
                preConfirm: (pw) => { if (!pw || pw.length < 6) { Swal.showValidationMessage('At least 6 characters'); return false; } return pw; }
            }).then(res => {
                if (!res.isConfirmed) return;
                $.post('?wp_reset_password=1', { user_id: id, password: res.value }, function (r) {
                    if (r.error) { showNotification(r.error, 'error'); return; }
                    showNotification(r.message || 'Password reset', 'success');
                }).fail(() => showNotification('Reset failed', 'error'));
            });
        });

        $(document).on('click', '#wpCreateAdminBtn', function () {
            Swal.fire({
                title: 'Create Administrator',
                html: '<input id="caLogin" class="swal2-input" placeholder="Username">'
                    + '<input id="caEmail" class="swal2-input" placeholder="Email">'
                    + '<input id="caPass" type="password" class="swal2-input" placeholder="Password (min 6)">',
                showCancelButton: true, confirmButtonText: 'Create',
                preConfirm: () => {
                    const login = document.getElementById('caLogin').value.trim();
                    const email = document.getElementById('caEmail').value.trim();
                    const password = document.getElementById('caPass').value;
                    if (!login || !email || !password) { Swal.showValidationMessage('All fields are required'); return false; }
                    if (password.length < 6) { Swal.showValidationMessage('Password must be at least 6 characters'); return false; }
                    return { login, email, password };
                }
            }).then(res => {
                if (!res.isConfirmed) return;
                $.post('?wp_create_admin=1', res.value, function (r) {
                    if (r.error) { showNotification(r.error, 'error'); return; }
                    showNotification(r.message || 'Admin created', 'success');
                    $('#wpListAdminsBtn').click();
                }).fail(() => showNotification('Create failed', 'error'));
            });
        });

        // ---------- DATABASE EXPORT ----------
        $(document).on('click', '#dbExportBtn', function () {
            $('#dbExportResults').html('<i class="fas fa-spinner fa-spin"></i> Preparing export...');
            $.post('?db_export_start=1', {}, function (start) {
                if (start.error) { $('#dbExportResults').html('<div class="alert alert-danger">' + start.error + '</div>'); return; }
                const total = start.total;
                const sessionId = start.sessionId;
                function step() {
                    $.post('?db_export_process=1', { sessionId }, function (r) {
                        if (r && r.busy) { setTimeout(step, 300); return; }
                        if (r.error) { $('#dbExportResults').html('<div class="alert alert-danger">' + r.error + '</div>'); return; }
                        const pct = Math.round((r.progress || 0) * 100);
                        $('#dbExportResults').html('<div>Exporting... ' + pct + '% (' + r.tables_done + '/' + total + ' tables, ' + r.rows + ' rows)</div>');
                        if (r.finished) {
                            const sizeKb = Math.round((r.size || 0) / 1024);
                            $('#dbExportResults').html(
                                '<div class="alert alert-success"><strong>Export complete!</strong><br>'
                                + r.rows + ' rows, ' + sizeKb + ' KB<br>'
                                + '<a class="btn btn-sm btn-primary mt-2" href="?db_export_download=1&file='
                                + encodeURIComponent(r.file) + '"><i class="fas fa-download"></i> Download .sql</a></div>');
                            showNotification('Database export ready', 'success');
                        } else {
                            setTimeout(step, 100);
                        }
                    }).fail(() => $('#dbExportResults').html('<div class="alert alert-danger">Export request failed</div>'));
                }
                step();
            }).fail(() => $('#dbExportResults').html('<div class="alert alert-danger">Could not start export</div>'));
        });

        // ---------- CORE INTEGRITY CHECKER ----------
        $(document).on('click', '#integrityBtn', function () {
            $('#integrityResults').html('<i class="fas fa-spinner fa-spin"></i> Fetching checksums from WordPress.org...');
            $.post('?integrity_start=1', {}, function (start) {
                if (start.error) { $('#integrityResults').html('<div class="alert alert-danger">' + start.error + '</div>'); return; }
                const total = start.total;
                const sessionId = start.sessionId;
                function step() {
                    $.post('?integrity_process=1', { sessionId }, function (r) {
                        if (r && r.busy) { setTimeout(step, 300); return; }
                        if (r.error) { $('#integrityResults').html('<div class="alert alert-danger">' + r.error + '</div>'); return; }
                        const pct = Math.round((r.progress || 0) * 100);
                        $('#integrityResults').html('<div>Verifying core files (WP ' + start.version + ')... ' + pct + '% (' + r.checked + '/' + total + ')</div>');
                        if (r.finished) {
                            let html;
                            if (r.modified_count === 0 && r.missing_count === 0) {
                                html = '<div class="alert alert-success"><strong>All core files verified.</strong> No modified or missing files.</div>';
                            } else {
                                html = '<div class="alert alert-danger"><strong>' + r.modified_count + ' modified, ' + r.missing_count + ' missing core file(s).</strong></div>';
                                if (r.modified.length) {
                                    html += '<div style="margin-top:8px;"><strong>Modified:</strong><ul style="max-height:200px;overflow:auto;">';
                                    r.modified.forEach(f => html += '<li>' + escapeHtml(f) + '</li>');
                                    html += '</ul></div>';
                                }
                                if (r.missing.length) {
                                    html += '<div style="margin-top:8px;"><strong>Missing:</strong><ul style="max-height:200px;overflow:auto;">';
                                    r.missing.forEach(f => html += '<li>' + escapeHtml(f) + '</li>');
                                    html += '</ul></div>';
                                }
                            }
                            $('#integrityResults').html(html);
                            showNotification('Integrity check complete', 'success');
                        } else {
                            setTimeout(step, 80);
                        }
                    }).fail(() => $('#integrityResults').html('<div class="alert alert-danger">Integrity request failed</div>'));
                }
                step();
            }).fail(() => $('#integrityResults').html('<div class="alert alert-danger">Could not start integrity check</div>'));
        });
    </script>
</body>
</html>