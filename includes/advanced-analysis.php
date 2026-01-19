<?php

/**
 * Advanced Spam Analysis Class
 *
 * File: includes/advanced-analysis.php
 * Contains advanced detection methods:
 * - Shannon entropy analysis
 * - Unicode homoglyph detection
 * - IP-based registration velocity
 * - Enhanced pattern matching
 * - Levenshtein similarity for username clusters
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_AdvancedAnalysis
{
  /**
   * Extended suspicious TLDs list
   */
  private static $suspicious_tlds = [
    // Free/cheap TLDs commonly abused
    '.tk', '.ml', '.ga', '.cf', '.gq',
    '.pw', '.cc', '.ws', '.xyz', '.top',
    '.buzz', '.click', '.link', '.work',
    '.site', '.online', '.live', '.store',
    '.icu', '.best', '.monster', '.rest',
    '.fit', '.uno', '.cam', '.bid',
    '.win', '.download', '.stream', '.racing',
    '.review', '.trade', '.webcam', '.date',
    '.faith', '.party', '.science', '.cricket',
    '.accountant', '.loan', '.men', '.gdn'
  ];

  /**
   * Unicode homoglyphs that look like ASCII
   * Used by spammers to bypass filters
   */
  private static $homoglyphs = [
    'а' => 'a', // Cyrillic
    'е' => 'e',
    'о' => 'o',
    'р' => 'p',
    'с' => 'c',
    'х' => 'x',
    'у' => 'y',
    'і' => 'i', // Ukrainian
    'ј' => 'j', // Serbian
    'ѕ' => 's',
    'ԁ' => 'd',
    'ɡ' => 'g', // Latin small letter script g
    'ɩ' => 'i',
    'ո' => 'n', // Armenian
    'ս' => 'u',
    'ԝ' => 'w',
    'ᴀ' => 'a', // Small caps
    'ʙ' => 'b',
    'ᴄ' => 'c',
    'ᴅ' => 'd',
    'ᴇ' => 'e',
    'ғ' => 'f',
    'ɢ' => 'g',
    'ʜ' => 'h',
    'ɪ' => 'i',
    'ᴊ' => 'j',
    'ᴋ' => 'k',
    'ʟ' => 'l',
    'ᴍ' => 'm',
    'ɴ' => 'n',
    'ᴏ' => 'o',
    'ᴘ' => 'p',
    'ǫ' => 'q',
    'ʀ' => 'r',
    's' => 's',
    'ᴛ' => 't',
    'ᴜ' => 'u',
    'ᴠ' => 'v',
    'ᴡ' => 'w',
    'х' => 'x',
    'ʏ' => 'y',
    'ᴢ' => 'z',
    '０' => '0', // Fullwidth
    '１' => '1',
    '２' => '2',
    '３' => '3',
    '４' => '4',
    '５' => '5',
    '６' => '6',
    '７' => '7',
    '８' => '8',
    '９' => '9',
  ];

  /**
   * Calculate Shannon entropy of a string
   * High entropy (>4.5) suggests random/bot-generated strings
   *
   * @param string $string Input string
   * @return float Entropy value (0-8 for ASCII)
   */
  public static function calculate_entropy($string)
  {
    if (empty($string)) {
      return 0;
    }

    $string = strtolower($string);
    $length = strlen($string);
    $frequencies = [];

    // Count character frequencies
    for ($i = 0; $i < $length; $i++) {
      $char = $string[$i];
      if (!isset($frequencies[$char])) {
        $frequencies[$char] = 0;
      }
      $frequencies[$char]++;
    }

    // Calculate entropy
    $entropy = 0;
    foreach ($frequencies as $count) {
      $probability = $count / $length;
      $entropy -= $probability * log($probability, 2);
    }

    return round($entropy, 2);
  }

  /**
   * Get entropy-based risk score
   *
   * @param string $username Username to analyze
   * @return array ['score' => int, 'entropy' => float, 'reason' => string|null]
   */
  public static function get_entropy_score($username)
  {
    $entropy = self::calculate_entropy($username);
    $result = [
      'score' => 0,
      'entropy' => $entropy,
      'reason' => null
    ];

    // Normal usernames have entropy between 2.5 and 4.0
    // Random strings typically have entropy > 4.5

    if ($entropy > 4.5 && strlen($username) >= 8) {
      $result['score'] = 25;
      $result['reason'] = sprintf('High entropy username (%.2f)', $entropy);
    } elseif ($entropy < 1.5 && strlen($username) >= 6) {
      // Very low entropy might indicate repetitive patterns
      $result['score'] = 15;
      $result['reason'] = sprintf('Repetitive username pattern (%.2f entropy)', $entropy);
    }

    return $result;
  }

  /**
   * Check for Unicode homoglyphs in username
   *
   * @param string $username Username to check
   * @return array ['has_homoglyphs' => bool, 'score' => int, 'converted' => string]
   */
  public static function check_homoglyphs($username)
  {
    $result = [
      'has_homoglyphs' => false,
      'score' => 0,
      'converted' => $username,
      'reason' => null
    ];

    $converted = $username;
    $found_homoglyphs = [];

    foreach (self::$homoglyphs as $homoglyph => $ascii) {
      if (mb_strpos($username, $homoglyph) !== false) {
        $found_homoglyphs[] = $homoglyph;
        $converted = str_replace($homoglyph, $ascii, $converted);
      }
    }

    if (!empty($found_homoglyphs)) {
      $result['has_homoglyphs'] = true;
      $result['score'] = 40;
      $result['converted'] = $converted;
      $result['reason'] = 'Unicode homoglyphs detected (spoofing attempt)';
    }

    return $result;
  }

  /**
   * Check email TLD against extended suspicious list
   *
   * @param string $email Email address
   * @return array ['is_suspicious' => bool, 'score' => int, 'tld' => string]
   */
  public static function check_suspicious_tld($email)
  {
    $result = [
      'is_suspicious' => false,
      'score' => 0,
      'tld' => '',
      'reason' => null
    ];

    $domain = strtolower(explode('@', $email)[1] ?? '');
    if (empty($domain)) {
      return $result;
    }

    // Extract TLD
    $parts = explode('.', $domain);
    $tld = '.' . end($parts);
    $result['tld'] = $tld;

    if (in_array($tld, self::$suspicious_tlds)) {
      $result['is_suspicious'] = true;
      $result['score'] = 20;
      $result['reason'] = sprintf('Suspicious TLD (%s)', $tld);
    }

    return $result;
  }

  /**
   * Find similar usernames using Levenshtein distance
   *
   * @param string $username Target username
   * @param int $threshold Maximum edit distance (default: 2)
   * @return array ['similar_count' => int, 'similar_usernames' => array, 'score' => int]
   */
  public static function find_similar_usernames($username, $threshold = 2)
  {
    global $wpdb;

    $result = [
      'similar_count' => 0,
      'similar_usernames' => [],
      'score' => 0,
      'reason' => null
    ];

    $username_lower = strtolower($username);

    // Get users with similar length usernames (optimization)
    $min_len = max(1, strlen($username) - $threshold);
    $max_len = strlen($username) + $threshold;

    $potential_matches = $wpdb->get_col($wpdb->prepare(
      "SELECT user_login FROM {$wpdb->users}
       WHERE CHAR_LENGTH(user_login) BETWEEN %d AND %d
       AND user_login != %s
       LIMIT 500",
      $min_len,
      $max_len,
      $username
    ));

    $similar = [];
    foreach ($potential_matches as $match) {
      $distance = levenshtein(strtolower($match), $username_lower);
      if ($distance <= $threshold && $distance > 0) {
        $similar[] = $match;
      }
    }

    $result['similar_count'] = count($similar);
    $result['similar_usernames'] = array_slice($similar, 0, 10); // Limit display

    if ($result['similar_count'] >= 5) {
      $result['score'] = 25;
      $result['reason'] = sprintf('Part of username cluster (%d similar)', $result['similar_count']);
    } elseif ($result['similar_count'] >= 3) {
      $result['score'] = 15;
      $result['reason'] = sprintf('Similar to %d other usernames', $result['similar_count']);
    }

    return $result;
  }

  /**
   * Track and analyze registration velocity by IP
   *
   * @param string $ip IP address
   * @param string $registration_time Registration timestamp
   * @return array ['registrations_24h' => int, 'score' => int]
   */
  public static function check_ip_registration_velocity($ip, $registration_time = null)
  {
    global $wpdb;

    $result = [
      'registrations_24h' => 0,
      'registrations_1h' => 0,
      'score' => 0,
      'reason' => null
    ];

    if (empty($ip) || $ip === '127.0.0.1' || $ip === '::1') {
      return $result;
    }

    // Check if we're storing registration IPs
    $settings = get_option('spam_detective_settings', []);
    if (empty($settings['track_registration_ip'])) {
      return $result;
    }

    $reg_time = $registration_time ? strtotime($registration_time) : time();

    // Get registrations from same IP in last 24 hours
    $registrations = $wpdb->get_var($wpdb->prepare(
      "SELECT COUNT(*) FROM {$wpdb->usermeta}
       WHERE meta_key = 'spam_detective_registration_ip'
       AND meta_value = %s",
      $ip
    ));

    $result['registrations_24h'] = intval($registrations);

    // Score based on registration count
    if ($result['registrations_24h'] >= 10) {
      $result['score'] = 40;
      $result['reason'] = sprintf('High registration velocity (%d from same IP)', $result['registrations_24h']);
    } elseif ($result['registrations_24h'] >= 5) {
      $result['score'] = 25;
      $result['reason'] = sprintf('Multiple registrations from IP (%d)', $result['registrations_24h']);
    } elseif ($result['registrations_24h'] >= 3) {
      $result['score'] = 15;
      $result['reason'] = sprintf('Several registrations from IP (%d)', $result['registrations_24h']);
    }

    return $result;
  }

  /**
   * Store registration IP for new users
   *
   * @param int $user_id User ID
   * @param string|null $ip IP address (defaults to current request IP)
   */
  public static function store_registration_ip($user_id, $ip = null)
  {
    $settings = get_option('spam_detective_settings', []);
    if (empty($settings['track_registration_ip'])) {
      return;
    }

    if ($ip === null) {
      $ip = self::get_client_ip();
    }

    if ($ip && $ip !== '127.0.0.1' && $ip !== '::1') {
      update_user_meta($user_id, 'spam_detective_registration_ip', $ip);
      update_user_meta($user_id, 'spam_detective_registration_time', current_time('mysql'));
    }
  }

  /**
   * Get client IP address
   *
   * @return string|null IP address
   */
  public static function get_client_ip()
  {
    $ip_keys = [
      'HTTP_CF_CONNECTING_IP', // Cloudflare
      'HTTP_X_FORWARDED_FOR',
      'HTTP_X_REAL_IP',
      'REMOTE_ADDR'
    ];

    foreach ($ip_keys as $key) {
      if (!empty($_SERVER[$key])) {
        $ip = $_SERVER[$key];
        // Handle comma-separated IPs (X-Forwarded-For)
        if (strpos($ip, ',') !== false) {
          $ip = trim(explode(',', $ip)[0]);
        }
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
          return $ip;
        }
      }
    }

    return null;
  }

  /**
   * Analyze username for keyboard walk patterns
   * Common in bot registrations: qwerty, asdfgh, zxcvbn
   *
   * @param string $username Username to check
   * @return array ['has_pattern' => bool, 'score' => int]
   */
  public static function check_keyboard_patterns($username)
  {
    $result = [
      'has_pattern' => false,
      'score' => 0,
      'reason' => null
    ];

    $patterns = [
      'qwerty', 'qwertz', 'azerty',
      'asdfgh', 'asdf', 'zxcvbn',
      '123456', '12345', '1234',
      'abcdef', 'abcd',
      'password', 'pass123', 'admin',
      'qazwsx', 'wsxedc'
    ];

    $username_lower = strtolower($username);

    foreach ($patterns as $pattern) {
      if (strpos($username_lower, $pattern) !== false) {
        $result['has_pattern'] = true;
        $result['score'] = 20;
        $result['reason'] = 'Keyboard pattern in username';
        break;
      }
    }

    return $result;
  }

  /**
   * Run all advanced analysis on a user
   *
   * @param object $user WordPress user object
   * @return array Combined results
   */
  public static function run_all_analysis($user)
  {
    $results = [
      'entropy' => null,
      'homoglyphs' => null,
      'tld_check' => null,
      'similar_usernames' => null,
      'ip_velocity' => null,
      'keyboard_patterns' => null,
      'total_score' => 0,
      'reasons' => []
    ];

    // Entropy analysis
    $entropy = self::get_entropy_score($user->user_login);
    $results['entropy'] = $entropy;
    if ($entropy['score'] > 0) {
      $results['total_score'] += $entropy['score'];
      $results['reasons'][] = $entropy['reason'];
    }

    // Homoglyph check
    $homoglyphs = self::check_homoglyphs($user->user_login);
    $results['homoglyphs'] = $homoglyphs;
    if ($homoglyphs['score'] > 0) {
      $results['total_score'] += $homoglyphs['score'];
      $results['reasons'][] = $homoglyphs['reason'];
    }

    // TLD check
    $tld = self::check_suspicious_tld($user->user_email);
    $results['tld_check'] = $tld;
    if ($tld['score'] > 0) {
      $results['total_score'] += $tld['score'];
      $results['reasons'][] = $tld['reason'];
    }

    // Keyboard patterns
    $keyboard = self::check_keyboard_patterns($user->user_login);
    $results['keyboard_patterns'] = $keyboard;
    if ($keyboard['score'] > 0) {
      $results['total_score'] += $keyboard['score'];
      $results['reasons'][] = $keyboard['reason'];
    }

    // Similar usernames (can be resource intensive)
    $settings = get_option('spam_detective_settings', []);
    if (!empty($settings['enable_similarity_check'])) {
      $similar = self::find_similar_usernames($user->user_login);
      $results['similar_usernames'] = $similar;
      if ($similar['score'] > 0) {
        $results['total_score'] += $similar['score'];
        $results['reasons'][] = $similar['reason'];
      }
    }

    // IP velocity check
    $registration_ip = get_user_meta($user->ID, 'spam_detective_registration_ip', true);
    if ($registration_ip) {
      $ip_velocity = self::check_ip_registration_velocity($registration_ip, $user->user_registered);
      $results['ip_velocity'] = $ip_velocity;
      if ($ip_velocity['score'] > 0) {
        $results['total_score'] += $ip_velocity['score'];
        $results['reasons'][] = $ip_velocity['reason'];
      }
    }

    return $results;
  }

  /**
   * Get list of suspicious TLDs
   *
   * @return array
   */
  public static function get_suspicious_tlds()
  {
    return self::$suspicious_tlds;
  }
}

// Hook to store registration IP for new users
add_action('user_register', function ($user_id) {
  SpamDetective_AdvancedAnalysis::store_registration_ip($user_id);
}, 10, 1);
