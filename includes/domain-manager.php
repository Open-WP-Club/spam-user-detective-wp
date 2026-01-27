<?php

/**
 * Domain Management Class
 * 
 * File: includes/domain-manager.php
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_DomainManager
{
  private $cache_manager;

  /**
   * In-memory cache for domain lists (per-request)
   */
  private $whitelist_cache = null;
  private $suspicious_cache = null;

  public function __construct($cache_manager = null)
  {
    $this->cache_manager = $cache_manager;
  }

  /**
   * Get whitelist domains (cached per-request)
   */
  public function get_whitelist()
  {
    if ($this->whitelist_cache === null) {
      $this->whitelist_cache = array_map('strtolower', get_option('spam_detective_whitelist', []));
    }
    return $this->whitelist_cache;
  }

  /**
   * Get suspicious domains (cached per-request)
   */
  public function get_suspicious_domains()
  {
    if ($this->suspicious_cache === null) {
      $this->suspicious_cache = array_map('strtolower', get_option('spam_detective_suspicious_domains', []));
    }
    return $this->suspicious_cache;
  }

  /**
   * Clear in-memory domain list caches
   */
  private function clear_domain_cache()
  {
    $this->whitelist_cache = null;
    $this->suspicious_cache = null;
  }

  /**
   * Add domain to whitelist
   */
  public function add_to_whitelist($domain)
  {
    $domain = strtolower(trim($domain));
    $whitelist = $this->get_whitelist();

    if (!in_array($domain, $whitelist)) {
      $whitelist[] = $domain;
      update_option('spam_detective_whitelist', $whitelist);

      $this->clear_domain_cache();

      if ($this->cache_manager) {
        $this->cache_manager->clear_all_user_cache();
      }

      return true;
    }

    return false;
  }

  /**
   * Remove domain from whitelist
   */
  public function remove_from_whitelist($domain)
  {
    $domain = strtolower(trim($domain));
    $whitelist = $this->get_whitelist();
    $original_count = count($whitelist);

    $whitelist = array_filter($whitelist, function ($d) use ($domain) {
      return $d !== $domain;
    });

    if (count($whitelist) < $original_count) {
      update_option('spam_detective_whitelist', array_values($whitelist));

      $this->clear_domain_cache();

      if ($this->cache_manager) {
        $this->cache_manager->clear_all_user_cache();
      }

      return true;
    }

    return false;
  }

  /**
   * Add domain to suspicious list
   */
  public function add_to_suspicious($domain)
  {
    $domain = strtolower(trim($domain));
    $suspicious_domains = $this->get_suspicious_domains();

    if (!in_array($domain, $suspicious_domains)) {
      $suspicious_domains[] = $domain;
      update_option('spam_detective_suspicious_domains', $suspicious_domains);

      $this->clear_domain_cache();

      if ($this->cache_manager) {
        $this->cache_manager->clear_all_user_cache();
      }

      return true;
    }

    return false;
  }

  /**
   * Remove domain from suspicious list
   */
  public function remove_from_suspicious($domain)
  {
    $domain = strtolower(trim($domain));
    $suspicious_domains = $this->get_suspicious_domains();
    $original_count = count($suspicious_domains);

    $suspicious_domains = array_filter($suspicious_domains, function ($d) use ($domain) {
      return $d !== $domain;
    });

    if (count($suspicious_domains) < $original_count) {
      update_option('spam_detective_suspicious_domains', array_values($suspicious_domains));

      $this->clear_domain_cache();

      if ($this->cache_manager) {
        $this->cache_manager->clear_all_user_cache();
      }

      return true;
    }

    return false;
  }

  /**
   * Check if domain is whitelisted
   */
  public function is_whitelisted($domain)
  {
    $domain = strtolower($domain);
    return in_array($domain, $this->get_whitelist());
  }

  /**
   * Check if domain is suspicious
   */
  public function is_suspicious($domain)
  {
    $domain = strtolower($domain);
    return in_array($domain, $this->get_suspicious_domains());
  }

  /**
   * Validate domain format
   */
  public function is_valid_domain($domain)
  {
    // Basic domain regex - allows domains like example.com, sub.example.com, etc.
    $domainRegex = '/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.([a-zA-Z]{2,}\.)*[a-zA-Z]{2,}$/';
    return preg_match($domainRegex, $domain);
  }

  /**
   * Export domain lists
   */
  public function export_domain_lists()
  {
    return [
      'exported_at' => current_time('mysql'),
      'whitelist' => $this->get_whitelist(),
      'suspicious_domains' => $this->get_suspicious_domains()
    ];
  }

  /**
   * Import domain lists
   */
  public function import_domain_lists($import_data, $merge_mode = 'replace')
  {
    $result = ['imported' => false, 'message' => ''];

    // Import whitelist
    if (isset($import_data['whitelist']) && is_array($import_data['whitelist'])) {
      if ($merge_mode === 'merge') {
        $current_whitelist = $this->get_whitelist();
        $new_whitelist = array_unique(array_merge($current_whitelist, $import_data['whitelist']));
      } else {
        $new_whitelist = array_map('strtolower', $import_data['whitelist']);
      }
      update_option('spam_detective_whitelist', $new_whitelist);
    }

    // Import suspicious domains
    if (isset($import_data['suspicious_domains']) && is_array($import_data['suspicious_domains'])) {
      if ($merge_mode === 'merge') {
        $current_suspicious = $this->get_suspicious_domains();
        $new_suspicious = array_unique(array_merge($current_suspicious, $import_data['suspicious_domains']));
      } else {
        $new_suspicious = array_map('strtolower', $import_data['suspicious_domains']);
      }
      update_option('spam_detective_suspicious_domains', $new_suspicious);
    }

    $this->clear_domain_cache();

    if ($this->cache_manager) {
      $this->cache_manager->clear_all_user_cache();
    }

    return ['imported' => true, 'message' => 'Domain lists imported successfully'];
  }
}
