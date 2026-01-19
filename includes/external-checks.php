<?php

/**
 * External Spam Checks Class
 *
 * File: includes/external-checks.php
 * Handles external API integrations for spam detection:
 * - StopForumSpam API
 * - Email MX Record validation
 * - Gravatar existence check
 * - IP reputation checks
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_ExternalChecks
{
  /**
   * Cache duration for external API results (in seconds)
   */
  const CACHE_DURATION = 86400; // 24 hours

  /**
   * StopForumSpam API timeout
   */
  const API_TIMEOUT = 5;

  /**
   * Check email against StopForumSpam database
   *
   * @param string $email Email address to check
   * @return array Result with 'is_spam', 'confidence', and 'frequency'
   */
  public static function check_stopforumspam($email)
  {
    $cache_key = 'spam_detective_sfs_' . md5($email);
    $cached = get_transient($cache_key);

    if ($cached !== false) {
      return $cached;
    }

    $result = [
      'is_spam' => false,
      'confidence' => 0,
      'frequency' => 0,
      'checked' => false,
      'error' => null
    ];

    // Check if external checks are enabled
    $settings = get_option('spam_detective_settings', []);
    if (empty($settings['enable_stopforumspam'])) {
      return $result;
    }

    $api_url = 'https://api.stopforumspam.org/api?email=' . urlencode($email) . '&json';

    $response = wp_remote_get($api_url, [
      'timeout' => self::API_TIMEOUT,
      'sslverify' => true
    ]);

    if (is_wp_error($response)) {
      $result['error'] = $response->get_error_message();
      error_log('Spam Detective: StopForumSpam API error - ' . $result['error']);
      return $result;
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if ($data && isset($data['success']) && $data['success'] == 1) {
      $result['checked'] = true;

      if (isset($data['email']) && $data['email']['appears'] == 1) {
        $result['is_spam'] = true;
        $result['confidence'] = floatval($data['email']['confidence'] ?? 0);
        $result['frequency'] = intval($data['email']['frequency'] ?? 0);
      }
    }

    // Cache the result
    set_transient($cache_key, $result, self::CACHE_DURATION);

    return $result;
  }

  /**
   * Get risk score from StopForumSpam result
   *
   * @param string $email Email address
   * @return int Risk score (0-50 based on confidence)
   */
  public static function get_stopforumspam_score($email)
  {
    $result = self::check_stopforumspam($email);

    if (!$result['is_spam']) {
      return 0;
    }

    // Scale confidence to a max of 50 points
    $confidence = min($result['confidence'], 100);
    return intval(($confidence / 100) * 50);
  }

  /**
   * Check if email domain has valid MX records
   *
   * @param string $email Email address
   * @return array Result with 'has_mx', 'mx_records'
   */
  public static function check_mx_records($email)
  {
    $cache_key = 'spam_detective_mx_' . md5($email);
    $cached = get_transient($cache_key);

    if ($cached !== false) {
      return $cached;
    }

    $result = [
      'has_mx' => true,
      'mx_records' => [],
      'checked' => false
    ];

    // Check if MX checks are enabled
    $settings = get_option('spam_detective_settings', []);
    if (empty($settings['enable_mx_check'])) {
      return $result;
    }

    // Extract domain
    $domain = strtolower(explode('@', $email)[1] ?? '');

    if (empty($domain)) {
      return $result;
    }

    $result['checked'] = true;

    // Check MX records
    $mx_hosts = [];
    $mx_weights = [];

    if (getmxrr($domain, $mx_hosts, $mx_weights)) {
      $result['has_mx'] = true;
      $result['mx_records'] = $mx_hosts;
    } else {
      // Fall back to A record check
      $a_record = gethostbyname($domain);
      if ($a_record !== $domain) {
        $result['has_mx'] = true;
        $result['mx_records'] = [$a_record . ' (A record)'];
      } else {
        $result['has_mx'] = false;
      }
    }

    // Cache the result
    set_transient($cache_key, $result, self::CACHE_DURATION);

    return $result;
  }

  /**
   * Get risk score for MX record check
   *
   * @param string $email Email address
   * @return int Risk score (0 or 35 if no MX)
   */
  public static function get_mx_score($email)
  {
    $result = self::check_mx_records($email);

    if (!$result['checked']) {
      return 0;
    }

    return $result['has_mx'] ? 0 : 35;
  }

  /**
   * Check if user has a Gravatar
   *
   * @param string $email Email address
   * @return array Result with 'has_gravatar'
   */
  public static function check_gravatar($email)
  {
    $cache_key = 'spam_detective_gravatar_' . md5($email);
    $cached = get_transient($cache_key);

    if ($cached !== false) {
      return $cached;
    }

    $result = [
      'has_gravatar' => false,
      'checked' => false
    ];

    // Check if Gravatar checks are enabled
    $settings = get_option('spam_detective_settings', []);
    if (empty($settings['enable_gravatar_check'])) {
      return $result;
    }

    $hash = md5(strtolower(trim($email)));
    $url = 'https://www.gravatar.com/avatar/' . $hash . '?d=404&s=1';

    $response = wp_remote_head($url, [
      'timeout' => self::API_TIMEOUT
    ]);

    $result['checked'] = true;

    if (!is_wp_error($response)) {
      $code = wp_remote_retrieve_response_code($response);
      $result['has_gravatar'] = ($code === 200);
    }

    // Cache the result
    set_transient($cache_key, $result, self::CACHE_DURATION);

    return $result;
  }

  /**
   * Get risk modifier for Gravatar (negative = reduces risk)
   *
   * @param string $email Email address
   * @return int Risk modifier (-10 if has Gravatar, +5 if no Gravatar for old accounts)
   */
  public static function get_gravatar_modifier($email, $user_registered = null)
  {
    $result = self::check_gravatar($email);

    if (!$result['checked']) {
      return 0;
    }

    if ($result['has_gravatar']) {
      return -10; // Having a Gravatar is a good sign
    }

    // If account is old and no Gravatar, slightly suspicious
    if ($user_registered) {
      $days_old = (time() - strtotime($user_registered)) / (60 * 60 * 24);
      if ($days_old > 30) {
        return 5;
      }
    }

    return 0;
  }

  /**
   * Check IP against StopForumSpam
   *
   * @param string $ip IP address to check
   * @return array Result with 'is_spam', 'confidence', 'frequency'
   */
  public static function check_ip_stopforumspam($ip)
  {
    if (empty($ip) || $ip === '127.0.0.1' || $ip === '::1') {
      return [
        'is_spam' => false,
        'confidence' => 0,
        'frequency' => 0,
        'checked' => false
      ];
    }

    $cache_key = 'spam_detective_sfs_ip_' . md5($ip);
    $cached = get_transient($cache_key);

    if ($cached !== false) {
      return $cached;
    }

    $result = [
      'is_spam' => false,
      'confidence' => 0,
      'frequency' => 0,
      'checked' => false,
      'error' => null
    ];

    // Check if external checks are enabled
    $settings = get_option('spam_detective_settings', []);
    if (empty($settings['enable_stopforumspam'])) {
      return $result;
    }

    $api_url = 'https://api.stopforumspam.org/api?ip=' . urlencode($ip) . '&json';

    $response = wp_remote_get($api_url, [
      'timeout' => self::API_TIMEOUT,
      'sslverify' => true
    ]);

    if (is_wp_error($response)) {
      $result['error'] = $response->get_error_message();
      return $result;
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if ($data && isset($data['success']) && $data['success'] == 1) {
      $result['checked'] = true;

      if (isset($data['ip']) && $data['ip']['appears'] == 1) {
        $result['is_spam'] = true;
        $result['confidence'] = floatval($data['ip']['confidence'] ?? 0);
        $result['frequency'] = intval($data['ip']['frequency'] ?? 0);
      }
    }

    // Cache the result
    set_transient($cache_key, $result, self::CACHE_DURATION);

    return $result;
  }

  /**
   * Run all external checks on a user
   *
   * @param object $user WordPress user object
   * @param string|null $registration_ip IP address at registration (if stored)
   * @return array Combined results and total score
   */
  public static function run_all_checks($user, $registration_ip = null)
  {
    $results = [
      'stopforumspam_email' => null,
      'stopforumspam_ip' => null,
      'mx_check' => null,
      'gravatar' => null,
      'total_score' => 0,
      'reasons' => []
    ];

    // StopForumSpam email check
    $sfs_result = self::check_stopforumspam($user->user_email);
    $results['stopforumspam_email'] = $sfs_result;

    if ($sfs_result['is_spam']) {
      $score = self::get_stopforumspam_score($user->user_email);
      $results['total_score'] += $score;
      $results['reasons'][] = sprintf(
        'StopForumSpam: %d%% confidence (%d reports)',
        round($sfs_result['confidence']),
        $sfs_result['frequency']
      );
    }

    // StopForumSpam IP check (if IP available)
    if ($registration_ip) {
      $sfs_ip_result = self::check_ip_stopforumspam($registration_ip);
      $results['stopforumspam_ip'] = $sfs_ip_result;

      if ($sfs_ip_result['is_spam']) {
        $ip_score = intval(($sfs_ip_result['confidence'] / 100) * 30);
        $results['total_score'] += $ip_score;
        $results['reasons'][] = sprintf(
          'IP flagged in StopForumSpam (%d reports)',
          $sfs_ip_result['frequency']
        );
      }
    }

    // MX record check
    $mx_result = self::check_mx_records($user->user_email);
    $results['mx_check'] = $mx_result;

    if ($mx_result['checked'] && !$mx_result['has_mx']) {
      $results['total_score'] += 35;
      $results['reasons'][] = 'Invalid email domain (no MX records)';
    }

    // Gravatar check
    $gravatar_result = self::check_gravatar($user->user_email);
    $results['gravatar'] = $gravatar_result;

    $gravatar_modifier = self::get_gravatar_modifier($user->user_email, $user->user_registered);
    $results['total_score'] += $gravatar_modifier;

    if ($gravatar_modifier < 0) {
      // Don't add as a reason - it's positive
    } elseif ($gravatar_modifier > 0) {
      $results['reasons'][] = 'No Gravatar for old account';
    }

    return $results;
  }

  /**
   * Clear all external check caches for a user
   *
   * @param string $email Email address
   * @param string|null $ip IP address
   */
  public static function clear_cache($email, $ip = null)
  {
    delete_transient('spam_detective_sfs_' . md5($email));
    delete_transient('spam_detective_mx_' . md5($email));
    delete_transient('spam_detective_gravatar_' . md5($email));

    if ($ip) {
      delete_transient('spam_detective_sfs_ip_' . md5($ip));
    }
  }
}
