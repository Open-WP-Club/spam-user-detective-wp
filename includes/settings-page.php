<?php

/**
 * Settings Page Class
 *
 * File: includes/settings-page.php
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_SettingsPage
{
  public function display_page()
  {
    $settings = get_option('spam_detective_settings', []);
?>
    <div class="wrap spam-detective-settings">
      <h1>Spam User Detective - Settings</h1>
      <p class="description">Configure detection methods, manage domain lists, and import/export settings.</p>

      <div class="settings-layout">
        <div class="settings-main">

          <!-- Detection Methods -->
          <div class="settings-card">
            <h2>Detection Methods</h2>

            <div class="settings-section">
              <h3>Basic Detection</h3>
              <p class="section-description">Core detection methods (always enabled)</p>
              <ul class="detection-list">
                <li><span class="status-dot enabled"></span> Username pattern analysis</li>
                <li><span class="status-dot enabled"></span> Email pattern analysis</li>
                <li><span class="status-dot enabled"></span> Display name analysis</li>
                <li><span class="status-dot enabled"></span> Bulk registration detection</li>
                <li><span class="status-dot enabled"></span> Registration burst detection</li>
                <li><span class="status-dot enabled"></span> User activity analysis</li>
              </ul>
            </div>

            <div class="settings-section">
              <h3>Advanced Detection</h3>
              <p class="section-description">Additional detection methods for better accuracy</p>

              <label class="toggle-row">
                <input type="checkbox" id="enable-disposable" <?php checked(!empty($settings['enable_disposable_check'])); ?>>
                <span class="toggle-label">Disposable Email Detection</span>
                <span class="toggle-info"><?php echo class_exists('SpamDetective_DisposableEmailChecker') ? '(' . SpamDetective_DisposableEmailChecker::get_domain_count() . ' known providers)' : ''; ?></span>
              </label>

              <label class="toggle-row">
                <input type="checkbox" id="enable-entropy" <?php checked(!empty($settings['enable_entropy_check'])); ?>>
                <span class="toggle-label">Username Entropy Analysis</span>
                <span class="toggle-info">Detects random/bot-generated names</span>
              </label>

              <label class="toggle-row">
                <input type="checkbox" id="enable-homoglyph" <?php checked(!empty($settings['enable_homoglyph_check'])); ?>>
                <span class="toggle-label">Unicode Homoglyph Detection</span>
                <span class="toggle-info">Detects spoofing attempts with lookalike characters</span>
              </label>

              <label class="toggle-row">
                <input type="checkbox" id="enable-similarity" <?php checked(!empty($settings['enable_similarity_check'])); ?>>
                <span class="toggle-label">Username Similarity Check</span>
                <span class="toggle-info">Finds username clusters (resource intensive)</span>
              </label>

              <label class="toggle-row">
                <input type="checkbox" id="track-registration-ip" <?php checked(!empty($settings['track_registration_ip'])); ?>>
                <span class="toggle-label">Track Registration IP</span>
                <span class="toggle-info">Enables IP velocity detection for new registrations</span>
              </label>
            </div>

            <div class="settings-section">
              <h3>External API Checks</h3>
              <p class="section-description">These checks query external services (requires internet connection)</p>

              <label class="toggle-row master-toggle">
                <input type="checkbox" id="enable-external" <?php checked(!empty($settings['enable_external_checks'])); ?>>
                <span class="toggle-label">Enable External Checks</span>
                <span class="toggle-info">Master toggle for all external APIs</span>
              </label>

              <div class="sub-toggles" <?php echo empty($settings['enable_external_checks']) ? 'style="opacity:0.5;pointer-events:none;"' : ''; ?>>
                <label class="toggle-row">
                  <input type="checkbox" id="enable-stopforumspam" <?php checked(!empty($settings['enable_stopforumspam'])); ?>>
                  <span class="toggle-label">StopForumSpam API</span>
                  <span class="toggle-info">Free spam database lookup</span>
                </label>

                <label class="toggle-row">
                  <input type="checkbox" id="enable-mx-check" <?php checked(!empty($settings['enable_mx_check'])); ?>>
                  <span class="toggle-label">Email MX Record Validation</span>
                  <span class="toggle-info">Checks if email domain is valid</span>
                </label>

                <label class="toggle-row">
                  <input type="checkbox" id="enable-gravatar" <?php checked(!empty($settings['enable_gravatar_check'])); ?>>
                  <span class="toggle-label">Gravatar Check</span>
                  <span class="toggle-info">Having a Gravatar reduces risk score</span>
                </label>
              </div>
            </div>

            <div class="settings-actions">
              <button id="save-detection-settings" class="button button-primary">Save Settings</button>
              <span id="settings-saved-notice" class="saved-notice" style="display:none;">Settings saved!</span>
            </div>
          </div>

          <!-- Risk Thresholds -->
          <div class="settings-card">
            <h2>Risk Thresholds</h2>
            <p class="section-description">Configure the score thresholds for risk levels</p>

            <div class="threshold-row">
              <label>
                <span class="threshold-label high">High Risk</span>
                <input type="number" id="threshold-high" value="<?php echo esc_attr($settings['risk_threshold_high'] ?? 70); ?>" min="1" max="200">
                <span class="threshold-info">Score ≥ this value</span>
              </label>
            </div>

            <div class="threshold-row">
              <label>
                <span class="threshold-label medium">Medium Risk</span>
                <input type="number" id="threshold-medium" value="<?php echo esc_attr($settings['risk_threshold_medium'] ?? 40); ?>" min="1" max="200">
                <span class="threshold-info">Score ≥ this value</span>
              </label>
            </div>

            <div class="threshold-row">
              <label>
                <span class="threshold-label low">Low Risk</span>
                <input type="number" id="threshold-low" value="<?php echo esc_attr($settings['risk_threshold_low'] ?? 25); ?>" min="1" max="200">
                <span class="threshold-info">Score ≥ this value (minimum to flag)</span>
              </label>
            </div>
          </div>

        </div>

        <div class="settings-sidebar">

          <!-- Domain Lists -->
          <div class="settings-card">
            <h2>Whitelisted Domains</h2>
            <p class="section-description">Domains that will never be flagged</p>
            <div id="whitelisted-domains" class="domain-list">
              <?php
              $whitelist = get_option('spam_detective_whitelist', []);
              foreach ($whitelist as $domain) {
                echo '<span class="domain-tag whitelist">' . esc_html($domain) . ' <button class="remove-domain" data-domain="' . esc_attr($domain) . '" data-type="whitelist">&times;</button></span>';
              }
              ?>
            </div>
            <div class="domain-input">
              <input type="text" id="new-whitelist-domain" placeholder="example.com">
              <button id="add-whitelist" class="button">Add</button>
            </div>
          </div>

          <div class="settings-card">
            <h2>Suspicious Domains</h2>
            <p class="section-description">Domains that will always be flagged</p>
            <div id="suspicious-domains" class="domain-list">
              <?php
              $suspicious = get_option('spam_detective_suspicious_domains', []);
              foreach ($suspicious as $domain) {
                echo '<span class="domain-tag suspicious">' . esc_html($domain) . ' <button class="remove-domain" data-domain="' . esc_attr($domain) . '" data-type="suspicious">&times;</button></span>';
              }
              ?>
            </div>
            <div class="domain-input">
              <input type="text" id="new-suspicious-domain" placeholder="spam-domain.com">
              <button id="add-suspicious" class="button">Add</button>
            </div>
          </div>

          <!-- Import/Export -->
          <div class="settings-card">
            <h2>Import / Export</h2>

            <div class="settings-section">
              <h3>Export Domain Lists</h3>
              <button id="export-domains" class="button">Export as JSON</button>
            </div>

            <div class="settings-section">
              <h3>Import Domain Lists</h3>
              <input type="file" id="import-file" accept=".json">
              <div class="import-options">
                <label><input type="radio" name="import_mode" value="replace" checked> Replace existing</label>
                <label><input type="radio" name="import_mode" value="merge"> Merge with existing</label>
              </div>
              <button id="import-domains" class="button">Import</button>
              <div id="import-status" class="import-status" style="display:none;"></div>
            </div>
          </div>

          <!-- Cache Management -->
          <div class="settings-card">
            <h2>Cache Management</h2>
            <p class="section-description">Analysis results are cached for 24 hours</p>
            <button id="clear-all-cache" class="button">Clear All Cache</button>
          </div>

          <!-- Protected Roles -->
          <div class="settings-card">
            <h2>Protected Roles</h2>
            <p class="section-description">These roles cannot be deleted</p>
            <div class="role-list">
              <span class="role-tag">Administrator</span>
              <span class="role-tag">Editor</span>
              <?php if (class_exists('WooCommerce')): ?>
                <span class="role-tag">Shop Manager</span>
              <?php endif; ?>
            </div>
          </div>

        </div>
      </div>
    </div>
<?php
  }
}
