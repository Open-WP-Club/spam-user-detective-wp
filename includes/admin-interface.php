<?php

/**
 * Admin Interface Class
 * 
 * File: includes/admin-interface.php
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_AdminInterface
{

  public function display_page()
  {
?>
    <div class="wrap spam-detective-wrap">
      <h1 class="spam-detective-title">Spam User Detective</h1>
      <p class="spam-detective-description">Detect and manage suspicious user accounts based on patterns commonly used by bots and spammers.</p>

      <?php $this->display_backup_warning(); ?>

      <div class="spam-detective-main">
        <div class="spam-detective-content">
          <?php $this->display_analysis_controls(); ?>
          <?php $this->display_results_container(); ?>
        </div>

        <div class="spam-detective-sidebar">
          <?php $this->display_settings(); ?>
          <?php $this->display_import_export(); ?>
        </div>
      </div>
    </div>
  <?php
  }

  private function display_backup_warning()
  {
  ?>
    <div class="notice notice-warning backup-warning">
      <p>
        <strong>Important:</strong> Please create a full backup of your website before using this tool.
        While we use multiple checks to identify spam accounts, false positives are always possible.
        Having a backup ensures you can restore legitimate users if they are accidentally removed.
      </p>
      <?php if (class_exists('WooCommerce')): ?>
        <p>
          <strong>WooCommerce Notice:</strong> Users with orders will be flagged but protected from deletion by default.
          Use "Force Delete" option with extreme caution.
        </p>
      <?php endif; ?>
    </div>
  <?php
  }

  private function display_analysis_controls()
  {
  ?>
    <div class="spam-detective-card">
      <h2>Analysis Controls</h2>
      <div class="analysis-buttons">
        <button id="analyze-users" class="button button-primary">Analyze All Users</button>
        <button id="quick-scan" class="button button-secondary">Quick Scan (Last 100)</button>
        <button id="clear-cache" class="button button-secondary">Clear Analysis Cache</button>
      </div>
      <div id="analysis-progress" class="analysis-progress" style="display:none;">
        <p>Analyzing users...</p>
        <div class="progress-bar">
          <div class="progress-fill"></div>
        </div>
      </div>
    </div>
  <?php
  }

  private function display_results_container()
  {
  ?>
    <div id="results-container" class="spam-detective-card" style="display:none;">
      <h2>Suspicious Users Found</h2>

      <div class="analysis-summary">
        <div class="summary-stat">
          <span class="stat-number" id="total-suspicious">0</span>
          <span class="stat-label">Suspicious Users</span>
        </div>
        <div class="summary-stat">
          <span class="stat-number" id="high-confidence">0</span>
          <span class="stat-label">High Confidence</span>
        </div>
        <div class="summary-stat">
          <span class="stat-number" id="suspicious-domains">0</span>
          <span class="stat-label">Bad Domains</span>
        </div>
        <div class="summary-stat">
          <span class="stat-number" id="protected-users">0</span>
          <span class="stat-label">Protected Users</span>
        </div>
      </div>

      <div class="bulk-actions">
        <div class="bulk-select-actions">
          <button id="select-all-high" class="button">Select All High Confidence</button>
          <button id="select-all-deletable" class="button">Select All Deletable</button>
          <button id="select-all-suspicious" class="button">Select All Suspicious</button>
        </div>

        <div class="bulk-main-actions">
          <button id="delete-selected" class="button button-primary delete-button">Delete Selected</button>
          <label class="force-delete-option">
            <input type="checkbox" id="force-delete-checkbox"> Force delete users with orders
          </label>
          <span id="selected-count" class="selected-count">0 selected</span>
        </div>

        <div class="bulk-export-actions">
          <button id="export-selected" class="button">Export Selected (CSV)</button>
          <button id="export-all" class="button">Export All Results (CSV)</button>
        </div>
      </div>

      <div class="tablenav">
        <div class="tablenav-pages">
          <span class="displaying-num" id="displaying-num">0 items</span>
        </div>
      </div>

      <table class="wp-list-table widefat fixed striped users">
        <thead>
          <tr>
            <th class="manage-column column-cb check-column">
              <input type="checkbox" id="select-all-checkbox">
            </th>
            <th>Status</th>
            <th>Risk Level</th>
            <th>Username</th>
            <th>Email</th>
            <th>Display Name</th>
            <th>Registration Date</th>
            <th>Risk Factors</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="suspicious-users-list">
          <!-- Results will be populated here -->
        </tbody>
      </table>
    </div>
  <?php
  }

  private function display_settings()
  {
    $settings = get_option('spam_detective_settings', []);
  ?>
    <div class="spam-detective-card">
      <h2>Settings</h2>

      <div class="settings-section">
        <h3>Protected Roles</h3>
        <p class="description">These user roles are automatically protected from deletion:</p>
        <div class="protected-roles-list">
          <span class="role-tag">Administrator</span>
          <span class="role-tag">Editor</span>
          <?php if (class_exists('WooCommerce')): ?>
            <span class="role-tag">Shop Manager</span>
          <?php endif; ?>
        </div>
      </div>

      <div class="settings-section">
        <h3>Whitelisted Domains</h3>
        <p class="description">Domains that should never be flagged as suspicious</p>
        <div id="whitelisted-domains" class="domain-list">
          <?php
          $whitelist = get_option('spam_detective_whitelist', []);
          foreach ($whitelist as $domain) {
            echo '<span class="domain-tag whitelist-tag">' . esc_html($domain) . ' <button class="remove-domain" data-domain="' . esc_attr($domain) . '" data-type="whitelist">×</button></span>';
          }
          ?>
        </div>
        <div class="domain-input">
          <input type="text" id="new-whitelist-domain" placeholder="Enter domain (e.g., gmail.com)" class="regular-text">
          <button id="add-whitelist" class="button">Add</button>
        </div>
      </div>

      <div class="settings-section">
        <h3>Suspicious Domains</h3>
        <p class="description">Domains that should be automatically flagged as suspicious</p>
        <div id="suspicious-domains" class="domain-list">
          <?php
          $suspicious = get_option('spam_detective_suspicious_domains', []);
          foreach ($suspicious as $domain) {
            echo '<span class="domain-tag suspicious-tag">' . esc_html($domain) . ' <button class="remove-domain" data-domain="' . esc_attr($domain) . '" data-type="suspicious">×</button></span>';
          }
          ?>
        </div>
        <div class="domain-input">
          <input type="text" id="new-suspicious-domain" placeholder="Enter domain (e.g., spam-domain.com)" class="regular-text">
          <button id="add-suspicious" class="button">Add</button>
        </div>
      </div>
    </div>

    <div class="spam-detective-card">
      <h2>Detection Methods <span class="version-badge">v1.4.0</span></h2>

      <div class="settings-section">
        <h3>Basic Detection</h3>
        <p class="description">Core detection methods (always enabled)</p>
        <ul class="detection-list">
          <li><span class="status-enabled">●</span> Username pattern analysis</li>
          <li><span class="status-enabled">●</span> Email pattern analysis</li>
          <li><span class="status-enabled">●</span> Display name analysis</li>
          <li><span class="status-enabled">●</span> Bulk registration detection</li>
          <li><span class="status-enabled">●</span> Registration burst detection</li>
          <li><span class="status-enabled">●</span> User activity analysis</li>
        </ul>
      </div>

      <div class="settings-section">
        <h3>Advanced Detection</h3>
        <p class="description">Additional detection methods for better accuracy</p>

        <label class="detection-toggle">
          <input type="checkbox" id="enable-disposable" <?php checked(!empty($settings['enable_disposable_check'])); ?>>
          <strong>Disposable Email Detection</strong>
          <span class="detection-info"><?php echo class_exists('SpamDetective_DisposableEmailChecker') ? '(' . SpamDetective_DisposableEmailChecker::get_domain_count() . ' known providers)' : ''; ?></span>
        </label>

        <label class="detection-toggle">
          <input type="checkbox" id="enable-entropy" <?php checked(!empty($settings['enable_entropy_check'])); ?>>
          <strong>Username Entropy Analysis</strong>
          <span class="detection-info">(Detects random/bot-generated names)</span>
        </label>

        <label class="detection-toggle">
          <input type="checkbox" id="enable-homoglyph" <?php checked(!empty($settings['enable_homoglyph_check'])); ?>>
          <strong>Unicode Homoglyph Detection</strong>
          <span class="detection-info">(Detects spoofing attempts)</span>
        </label>

        <label class="detection-toggle">
          <input type="checkbox" id="enable-similarity" <?php checked(!empty($settings['enable_similarity_check'])); ?>>
          <strong>Username Similarity Check</strong>
          <span class="detection-info">(Finds username clusters - resource intensive)</span>
        </label>

        <label class="detection-toggle">
          <input type="checkbox" id="track-registration-ip" <?php checked(!empty($settings['track_registration_ip'])); ?>>
          <strong>Track Registration IP</strong>
          <span class="detection-info">(Enables IP velocity detection)</span>
        </label>
      </div>

      <div class="settings-section">
        <h3>External API Checks</h3>
        <p class="description">These checks query external services (requires internet connection)</p>

        <label class="detection-toggle">
          <input type="checkbox" id="enable-external" <?php checked(!empty($settings['enable_external_checks'])); ?>>
          <strong>Enable External Checks</strong>
          <span class="detection-info">(Master toggle for all external APIs)</span>
        </label>

        <div class="external-checks-options" <?php echo empty($settings['enable_external_checks']) ? 'style="opacity:0.5;pointer-events:none;"' : ''; ?>>
          <label class="detection-toggle sub-toggle">
            <input type="checkbox" id="enable-stopforumspam" <?php checked(!empty($settings['enable_stopforumspam'])); ?>>
            <strong>StopForumSpam API</strong>
            <span class="detection-info">(Free spam database lookup)</span>
          </label>

          <label class="detection-toggle sub-toggle">
            <input type="checkbox" id="enable-mx-check" <?php checked(!empty($settings['enable_mx_check'])); ?>>
            <strong>Email MX Record Validation</strong>
            <span class="detection-info">(Checks if email domain is valid)</span>
          </label>

          <label class="detection-toggle sub-toggle">
            <input type="checkbox" id="enable-gravatar" <?php checked(!empty($settings['enable_gravatar_check'])); ?>>
            <strong>Gravatar Check</strong>
            <span class="detection-info">(Having a Gravatar reduces risk score)</span>
          </label>
        </div>
      </div>

      <div class="settings-actions">
        <button id="save-detection-settings" class="button button-primary">Save Detection Settings</button>
        <span id="settings-saved-notice" class="notice-inline" style="display:none;">Settings saved!</span>
      </div>
    </div>
  <?php
  }

  private function display_import_export()
  {
  ?>
    <div class="spam-detective-card">
      <h2>Import/Export</h2>

      <div class="settings-section">
        <h3>Export Domain Lists</h3>
        <p class="description">Download your whitelist and suspicious domain lists</p>
        <button id="export-domains" class="button button-secondary">Export Domain Lists</button>
      </div>

      <div class="settings-section">
        <h3>Import Domain Lists</h3>
        <p class="description">Upload a previously exported domain lists file</p>

        <div class="import-controls">
          <input type="file" id="import-file" accept=".json" style="margin-bottom: 10px;">

          <div class="import-options" style="margin-bottom: 10px;">
            <label>
              <input type="radio" name="import_mode" value="replace" checked> Replace existing lists
            </label>
            <label style="margin-left: 15px;">
              <input type="radio" name="import_mode" value="merge"> Merge with existing lists
            </label>
          </div>

          <button id="import-domains" class="button button-secondary">Import Domain Lists</button>
        </div>

        <div id="import-status" class="import-status" style="display:none; margin-top: 10px;"></div>
      </div>

      <div class="settings-section">
        <h3>Cache Management</h3>
        <p class="description">Analysis results are cached for 24 hours to improve performance</p>
        <button id="clear-all-cache" class="button button-secondary">Clear All Cache</button>
      </div>
    </div>
<?php
  }
}
