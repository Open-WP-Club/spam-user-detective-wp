<?php

/**
 * Utility Class for Spam Detective
 *
 * File: includes/utils.php
 * Provides shared utility methods to reduce code duplication.
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_Utils
{
  /**
   * Cached settings for the current request
   */
  private static $settings_cache = null;

  /**
   * Extract domain from email address (lowercase)
   *
   * @param string $email Email address
   * @return string Domain part of email, or empty string if invalid
   */
  public static function get_email_domain($email)
  {
    $parts = explode('@', $email);
    return isset($parts[1]) ? strtolower($parts[1]) : '';
  }

  /**
   * Extract prefix from email address
   *
   * @param string $email Email address
   * @return string Prefix part of email, or empty string if invalid
   */
  public static function get_email_prefix($email)
  {
    $parts = explode('@', $email);
    return $parts[0] ?? '';
  }

  /**
   * Get plugin settings with per-request caching
   *
   * @param string|null $key Specific setting key, or null for all settings
   * @param mixed $default Default value if key not found
   * @return mixed Settings array or specific setting value
   */
  public static function get_settings($key = null, $default = null)
  {
    if (self::$settings_cache === null) {
      self::$settings_cache = get_option('spam_detective_settings', []);
    }

    if ($key === null) {
      return self::$settings_cache;
    }

    return self::$settings_cache[$key] ?? $default;
  }

  /**
   * Check if a specific feature is enabled
   *
   * @param string $feature Feature key (e.g., 'enable_disposable_check')
   * @return bool
   */
  public static function is_feature_enabled($feature)
  {
    return !empty(self::get_settings($feature, false));
  }

  /**
   * Clear the settings cache (useful after settings update)
   */
  public static function clear_settings_cache()
  {
    self::$settings_cache = null;
  }

  /**
   * Get risk threshold for a given level
   *
   * @param string $level 'high', 'medium', or 'low'
   * @return int Threshold value
   */
  public static function get_risk_threshold($level)
  {
    $defaults = [
      'high' => 70,
      'medium' => 40,
      'low' => 25
    ];

    $key = 'risk_threshold_' . $level;
    return self::get_settings($key, $defaults[$level] ?? 25);
  }
}
