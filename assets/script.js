/**
 * Spam Detective Frontend Script
 * Version: 1.4.0 (Vanilla JS)
 *
 * File: assets/script.js
 */

(function() {
  'use strict';

  let suspiciousUsers = [];
  let selectedUsers = [];

  // =============================================
  // Utility Functions
  // =============================================

  function $(selector) {
    return document.querySelector(selector);
  }

  function $$(selector) {
    return document.querySelectorAll(selector);
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  function show(element) {
    if (element) element.style.display = '';
  }

  function hide(element) {
    if (element) element.style.display = 'none';
  }

  function fadeIn(element, duration = 300) {
    if (!element) return;
    element.style.opacity = '0';
    element.style.display = '';
    element.style.transition = `opacity ${duration}ms ease`;
    requestAnimationFrame(() => {
      element.style.opacity = '1';
    });
  }

  function fadeOut(element, duration = 300, callback) {
    if (!element) return;
    element.style.transition = `opacity ${duration}ms ease`;
    element.style.opacity = '0';
    setTimeout(() => {
      element.style.display = 'none';
      if (callback) callback();
    }, duration);
  }

  function ajax(options) {
    const { url, method = 'POST', data, success, error } = options;

    const formData = new FormData();
    if (data) {
      Object.keys(data).forEach(key => {
        const value = data[key];
        if (Array.isArray(value)) {
          value.forEach((v, i) => formData.append(`${key}[${i}]`, v));
        } else {
          formData.append(key, value);
        }
      });
    }

    fetch(url, {
      method,
      body: formData,
      credentials: 'same-origin'
    })
      .then(response => response.json())
      .then(response => {
        if (success) success(response);
      })
      .catch(err => {
        if (error) error(err);
      });
  }

  function ajaxWithFile(options) {
    const { url, formData, success, error } = options;

    fetch(url, {
      method: 'POST',
      body: formData,
      credentials: 'same-origin'
    })
      .then(response => response.json())
      .then(response => {
        if (success) success(response);
      })
      .catch(err => {
        if (error) error(err);
      });
  }

  function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  function isValidDomain(domain) {
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.([a-zA-Z]{2,}\.)*[a-zA-Z]{2,}$/;
    return domainRegex.test(domain);
  }

  // =============================================
  // Detection Settings Management
  // =============================================

  function initDetectionSettings() {
    const enableExternal = $('#enable-external');
    const externalOptions = $('.external-checks-options');

    if (enableExternal && externalOptions) {
      enableExternal.addEventListener('change', function() {
        if (this.checked) {
          externalOptions.style.opacity = '1';
          externalOptions.style.pointerEvents = 'auto';
        } else {
          externalOptions.style.opacity = '0.5';
          externalOptions.style.pointerEvents = 'none';
        }
      });
    }

    const saveSettingsBtn = $('#save-detection-settings');
    if (saveSettingsBtn) {
      saveSettingsBtn.addEventListener('click', saveDetectionSettings);
    }
  }

  function saveDetectionSettings() {
    const button = $('#save-detection-settings');
    const notice = $('#settings-saved-notice');

    button.disabled = true;
    button.textContent = 'Saving...';

    ajax({
      url: spamDetective.ajaxUrl,
      data: {
        action: 'save_detection_settings',
        nonce: spamDetective.nonce,
        enable_disposable: $('#enable-disposable')?.checked ? '1' : '',
        enable_entropy: $('#enable-entropy')?.checked ? '1' : '',
        enable_homoglyph: $('#enable-homoglyph')?.checked ? '1' : '',
        enable_similarity: $('#enable-similarity')?.checked ? '1' : '',
        track_registration_ip: $('#track-registration-ip')?.checked ? '1' : '',
        enable_external: $('#enable-external')?.checked ? '1' : '',
        enable_stopforumspam: $('#enable-stopforumspam')?.checked ? '1' : '',
        enable_mx_check: $('#enable-mx-check')?.checked ? '1' : '',
        enable_gravatar: $('#enable-gravatar')?.checked ? '1' : ''
      },
      success: function(response) {
        button.disabled = false;
        button.textContent = 'Save Detection Settings';

        if (response.success) {
          notice.textContent = 'Settings saved! Cache cleared.';
          fadeIn(notice);
          setTimeout(() => fadeOut(notice), 3000);

          if (suspiciousUsers.length > 0) {
            showTemporaryMessage('Detection settings changed. Run a new analysis to see updated results.', 'info');
          }
        } else {
          alert('Error saving settings: ' + response.data);
        }
      },
      error: function() {
        button.disabled = false;
        button.textContent = 'Save Detection Settings';
        alert('An error occurred while saving settings.');
      }
    });
  }

  // =============================================
  // Analysis Functions
  // =============================================

  function initAnalysis() {
    const analyzeBtn = $('#analyze-users');
    const quickScanBtn = $('#quick-scan');
    const clearCacheBtn = $('#clear-cache');
    const clearAllCacheBtn = $('#clear-all-cache');

    if (analyzeBtn) {
      analyzeBtn.addEventListener('click', () => startAnalysis(false));
    }
    if (quickScanBtn) {
      quickScanBtn.addEventListener('click', () => startAnalysis(true));
    }
    if (clearCacheBtn) {
      clearCacheBtn.addEventListener('click', clearCache);
    }
    if (clearAllCacheBtn) {
      clearAllCacheBtn.addEventListener('click', clearCache);
    }
  }

  function clearCache() {
    ajax({
      url: spamDetective.ajaxUrl,
      data: {
        action: 'clear_spam_cache',
        nonce: spamDetective.nonce
      },
      success: function(response) {
        alert('Cache cleared successfully. Next analysis will be slower but more accurate.');
      }
    });
  }

  function startAnalysis(isQuickScan) {
    const progress = $('#analysis-progress');
    const progressFill = $('.progress-fill');
    const resultsContainer = $('#results-container');

    show(progress);
    if (progressFill) progressFill.style.width = '0%';
    hide(resultsContainer);

    animateProgress();

    ajax({
      url: spamDetective.ajaxUrl,
      data: {
        action: 'analyze_spam_users',
        quick_scan: isQuickScan ? '1' : '',
        nonce: spamDetective.nonce
      },
      success: function(response) {
        hide(progress);
        if (response.success) {
          suspiciousUsers = response.data.users;
          displayResults();
          show(resultsContainer);
        } else {
          alert('Error: ' + response.data);
        }
      },
      error: function() {
        hide(progress);
        alert('An error occurred during analysis. Please try again.');
      }
    });
  }

  function animateProgress() {
    const progressFill = $('.progress-fill');
    if (!progressFill) return;

    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.random() * 15;
      if (progress > 90) progress = 90;
      progressFill.style.width = progress + '%';
      if (progress >= 90) {
        clearInterval(interval);
      }
    }, 200);
  }

  // =============================================
  // Results Display
  // =============================================

  function generateRiskFactorTags(reasons) {
    if (!reasons || reasons.length === 0) {
      return '<em>No factors detected</em>';
    }

    const highPriorityFactors = [
      'Known spam domain',
      'No display name',
      'Suspicious username pattern (multiple dots)',
      'Mass registration burst',
      'Bulk registration',
      'Disposable/temporary email',
      'StopForumSpam',
      'Invalid email domain',
      'Unicode homoglyphs',
      'High registration velocity',
      'IP flagged'
    ];

    const mediumPriorityFactors = [
      'Suspicious username pattern',
      'Random username',
      'Generic email pattern',
      'Suspicious domain extension',
      'Common spam username pattern',
      'Fake name used',
      'Sequential username pattern',
      'High entropy',
      'Suspicious TLD',
      'username cluster',
      'Keyboard pattern',
      'No Gravatar',
      'Multiple registrations from IP'
    ];

    let tags = '';
    reasons.forEach(reason => {
      let tagClass = 'risk-factor-tag';

      const isHighPriority = highPriorityFactors.some(pattern =>
        reason.toLowerCase().includes(pattern.toLowerCase())
      );

      const isMediumPriority = mediumPriorityFactors.some(pattern =>
        reason.toLowerCase().includes(pattern.toLowerCase())
      );

      if (isHighPriority) {
        tagClass += ' high-priority';
      } else if (isMediumPriority) {
        tagClass += ' medium-priority';
      }

      tags += `<span class="${tagClass}" title="${escapeHtml(reason)}">${escapeHtml(reason)}</span> `;
    });

    return tags;
  }

  function displayResults() {
    const highConfidence = suspiciousUsers.filter(u => u.risk_level === 'high').length;
    const domains = new Set(suspiciousUsers.map(u => u.email.split('@')[1]));
    const protectedUsers = suspiciousUsers.filter(u => !u.can_delete).length;

    const totalSuspicious = $('#total-suspicious');
    const highConfidenceEl = $('#high-confidence');
    const suspiciousDomainsEl = $('#suspicious-domains');
    const protectedUsersEl = $('#protected-users');
    const displayingNum = $('#displaying-num');

    if (totalSuspicious) totalSuspicious.textContent = suspiciousUsers.length;
    if (highConfidenceEl) highConfidenceEl.textContent = highConfidence;
    if (suspiciousDomainsEl) suspiciousDomainsEl.textContent = domains.size;
    if (protectedUsersEl) protectedUsersEl.textContent = protectedUsers;
    if (displayingNum) displayingNum.textContent = suspiciousUsers.length + ' items';

    let html = '';
    suspiciousUsers.forEach(user => {
      const riskClass = 'risk-' + user.risk_level;
      const emailDomain = user.email.split('@')[1];
      const statusIcon = getStatusIcon(user);
      const statusClass = getStatusClass(user);
      const riskFactorTags = generateRiskFactorTags(user.reasons);

      html += `
        <tr data-user-id="${user.id}" class="${statusClass}">
          <td><input type="checkbox" class="user-checkbox" value="${user.id}" ${!user.can_delete ? 'disabled' : ''}></td>
          <td>${statusIcon}</td>
          <td><span class="risk-level ${riskClass}">${user.risk_level}</span></td>
          <td><strong>${escapeHtml(user.username)}</strong></td>
          <td>${escapeHtml(user.email)}</td>
          <td>${user.display_name ? escapeHtml(user.display_name) : '<em>None</em>'}</td>
          <td>${user.registered}</td>
          <td class="risk-factors">${riskFactorTags}</td>
          <td>
            <button class="button button-small delete-single" data-user-id="${user.id}" ${!user.can_delete ? 'disabled' : ''}>Delete</button>
            <button class="button button-small whitelist-domain" data-domain="${emailDomain}">Whitelist Domain</button>
          </td>
        </tr>
      `;
    });

    const usersList = $('#suspicious-users-list');
    if (usersList) usersList.innerHTML = html;

    selectedUsers = [];
    const selectAllCheckbox = $('#select-all-checkbox');
    if (selectAllCheckbox) {
      selectAllCheckbox.checked = false;
      selectAllCheckbox.indeterminate = false;
    }
    updateSelectedCount();
  }

  function getStatusIcon(user) {
    if (!user.can_delete) {
      if (user.roles.includes('administrator') || user.roles.includes('editor') || user.roles.includes('shop_manager')) {
        return '<span class="status-icon protected-role" title="Protected Role">🛡️</span>';
      }
      return '<span class="status-icon protected" title="Protected User">🔒</span>';
    }
    if (user.has_orders) {
      return '<span class="status-icon has-orders" title="Has WooCommerce Orders">🛒</span>';
    }
    return '<span class="status-icon deletable" title="Can be deleted">⚠️</span>';
  }

  function getStatusClass(user) {
    if (!user.can_delete) return 'protected-user';
    if (user.has_orders) return 'user-with-orders';
    return 'deletable-user';
  }

  // =============================================
  // Checkbox Handling
  // =============================================

  function initCheckboxHandling() {
    document.addEventListener('change', function(e) {
      if (e.target.classList.contains('user-checkbox')) {
        updateSelectedCount();
      }
    });

    const selectAllCheckbox = $('#select-all-checkbox');
    if (selectAllCheckbox) {
      selectAllCheckbox.addEventListener('change', function() {
        const checkboxes = $$('.user-checkbox:not(:disabled)');
        checkboxes.forEach(cb => cb.checked = this.checked);
        updateSelectedCount();
      });
    }

    const selectAllHigh = $('#select-all-high');
    if (selectAllHigh) {
      selectAllHigh.addEventListener('click', function() {
        $$('.user-checkbox').forEach(cb => cb.checked = false);
        suspiciousUsers.forEach(user => {
          if (user.risk_level === 'high' && user.can_delete) {
            const cb = $(`.user-checkbox[value="${user.id}"]`);
            if (cb) cb.checked = true;
          }
        });
        updateSelectedCount();
      });
    }

    const selectAllDeletable = $('#select-all-deletable');
    if (selectAllDeletable) {
      selectAllDeletable.addEventListener('click', function() {
        $$('.user-checkbox').forEach(cb => cb.checked = false);
        suspiciousUsers.forEach(user => {
          if (user.can_delete && !user.has_orders) {
            const cb = $(`.user-checkbox[value="${user.id}"]`);
            if (cb) cb.checked = true;
          }
        });
        updateSelectedCount();
      });
    }

    const selectAllSuspicious = $('#select-all-suspicious');
    if (selectAllSuspicious) {
      selectAllSuspicious.addEventListener('click', function() {
        $$('.user-checkbox:not(:disabled)').forEach(cb => cb.checked = true);
        updateSelectedCount();
      });
    }
  }

  function updateSelectedCount() {
    selectedUsers = Array.from($$('.user-checkbox:checked')).map(cb => cb.value);
    const countEl = $('#selected-count');
    if (countEl) countEl.textContent = selectedUsers.length + ' selected';

    const totalEnabled = $$('.user-checkbox:not(:disabled)').length;
    const checkedCount = $$('.user-checkbox:checked').length;
    const selectAllCheckbox = $('#select-all-checkbox');

    if (selectAllCheckbox) {
      if (checkedCount === 0) {
        selectAllCheckbox.indeterminate = false;
        selectAllCheckbox.checked = false;
      } else if (checkedCount === totalEnabled) {
        selectAllCheckbox.indeterminate = false;
        selectAllCheckbox.checked = true;
      } else {
        selectAllCheckbox.indeterminate = true;
      }
    }
  }

  // =============================================
  // Delete Functions
  // =============================================

  function initDeleteHandling() {
    const deleteSelectedBtn = $('#delete-selected');
    if (deleteSelectedBtn) {
      deleteSelectedBtn.addEventListener('click', function() {
        if (selectedUsers.length === 0) {
          alert('Please select users to delete.');
          return;
        }
        const forceDelete = $('#force-delete-checkbox')?.checked || false;
        deleteUsers(selectedUsers, forceDelete);
      });
    }

    document.addEventListener('click', function(e) {
      if (e.target.classList.contains('delete-single')) {
        const userId = e.target.dataset.userId;
        deleteUsers([userId], true);
      }
    });
  }

  function deleteUsers(userIds, forceDelete = false) {
    ajax({
      url: spamDetective.ajaxUrl,
      data: {
        action: 'delete_spam_users',
        user_ids: userIds,
        force_delete: forceDelete ? '1' : '',
        nonce: spamDetective.nonce
      },
      success: function(response) {
        if (response.success) {
          alert(response.data.message || `Successfully deleted ${response.data.deleted} users.`);
          userIds.forEach(id => {
            const row = $(`tr[data-user-id="${id}"]`);
            if (row) row.remove();
          });
          suspiciousUsers = suspiciousUsers.filter(u => !userIds.includes(u.id.toString()));
          displayResults();
        } else {
          alert('Error deleting users: ' + response.data);
        }
      },
      error: function() {
        alert('An error occurred while deleting users. Please try again.');
      }
    });
  }

  // =============================================
  // Export Functions
  // =============================================

  function initExportHandling() {
    const exportSelectedBtn = $('#export-selected');
    if (exportSelectedBtn) {
      exportSelectedBtn.addEventListener('click', function() {
        if (selectedUsers.length === 0) {
          alert('Please select users to export.');
          return;
        }
        exportUsers(selectedUsers);
      });
    }

    const exportAllBtn = $('#export-all');
    if (exportAllBtn) {
      exportAllBtn.addEventListener('click', function() {
        if (suspiciousUsers.length === 0) {
          alert('No users to export.');
          return;
        }
        const allUserIds = suspiciousUsers.map(u => u.id.toString());
        exportUsers(allUserIds);
      });
    }

    const exportDomainsBtn = $('#export-domains');
    if (exportDomainsBtn) {
      exportDomainsBtn.addEventListener('click', exportDomainLists);
    }

    const importDomainsBtn = $('#import-domains');
    if (importDomainsBtn) {
      importDomainsBtn.addEventListener('click', importDomainLists);
    }
  }

  function exportUsers(userIds) {
    ajax({
      url: spamDetective.ajaxUrl,
      data: {
        action: 'export_suspicious_users',
        user_ids: userIds,
        nonce: spamDetective.nonce
      },
      success: function(response) {
        if (response.success) {
          downloadFile(response.data.content, response.data.filename, 'text/csv');
          alert(`Exported ${userIds.length} users successfully.`);
        } else {
          alert('Error exporting users: ' + response.data);
        }
      },
      error: function() {
        alert('An error occurred while exporting users. Please try again.');
      }
    });
  }

  function exportDomainLists() {
    ajax({
      url: spamDetective.ajaxUrl,
      data: {
        action: 'export_domain_lists',
        nonce: spamDetective.nonce
      },
      success: function(response) {
        if (response.success) {
          downloadFile(response.data.content, response.data.filename, 'application/json');
          alert('Domain lists exported successfully.');
        } else {
          alert('Error exporting domain lists: ' + response.data);
        }
      },
      error: function() {
        alert('An error occurred while exporting domain lists. Please try again.');
      }
    });
  }

  function importDomainLists() {
    const fileInput = document.getElementById('import-file');
    const file = fileInput?.files[0];

    if (!file) {
      alert('Please select a file to import.');
      return;
    }

    if (file.type !== 'application/json' && !file.name.endsWith('.json')) {
      alert('Please select a valid JSON file.');
      return;
    }

    const mergeMode = document.querySelector('input[name="import_mode"]:checked')?.value || 'replace';
    const importStatus = $('#import-status');

    const formData = new FormData();
    formData.append('action', 'import_domain_lists');
    formData.append('import_file', file);
    formData.append('merge_mode', mergeMode);
    formData.append('nonce', spamDetective.nonce);

    if (importStatus) {
      importStatus.textContent = 'Importing...';
      show(importStatus);
    }

    ajaxWithFile({
      url: spamDetective.ajaxUrl,
      formData: formData,
      success: function(response) {
        if (response.success) {
          if (importStatus) {
            importStatus.textContent = 'Import successful! Reloading page...';
            importStatus.classList.add('success');
          }
          setTimeout(() => location.reload(), 2000);
        } else {
          if (importStatus) {
            importStatus.textContent = 'Import failed: ' + response.data;
            importStatus.classList.add('error');
          }
        }
      },
      error: function() {
        if (importStatus) {
          importStatus.textContent = 'An error occurred during import.';
          importStatus.classList.add('error');
        }
      }
    });
  }

  // =============================================
  // Domain Management
  // =============================================

  function initDomainManagement() {
    document.addEventListener('click', function(e) {
      if (e.target.classList.contains('whitelist-domain')) {
        const domain = e.target.dataset.domain;
        manageDomain('whitelist', 'add', domain);
      }

      if (e.target.classList.contains('remove-domain')) {
        const domain = e.target.dataset.domain.toLowerCase();
        const type = e.target.dataset.type;
        const domainTag = e.target.closest('.domain-tag');

        if (domainTag) domainTag.style.opacity = '0.5';
        manageDomain(type, 'remove', domain, domainTag);
      }
    });

    const addWhitelistBtn = $('#add-whitelist');
    if (addWhitelistBtn) {
      addWhitelistBtn.addEventListener('click', function() {
        const input = $('#new-whitelist-domain');
        const domain = input?.value.trim().toLowerCase();

        if (domain) {
          if (!isValidDomain(domain)) {
            alert('Please enter a valid domain name (e.g., example.com)');
            return;
          }
          this.disabled = true;
          this.textContent = 'Adding...';
          manageDomain('whitelist', 'add', domain, null, this);
          input.value = '';
        } else {
          alert('Please enter a domain name');
        }
      });
    }

    const addSuspiciousBtn = $('#add-suspicious');
    if (addSuspiciousBtn) {
      addSuspiciousBtn.addEventListener('click', function() {
        const input = $('#new-suspicious-domain');
        const domain = input?.value.trim().toLowerCase();

        if (domain) {
          if (!isValidDomain(domain)) {
            alert('Please enter a valid domain name (e.g., example.com)');
            return;
          }
          this.disabled = true;
          this.textContent = 'Adding...';
          manageDomain('suspicious', 'add', domain, null, this);
          input.value = '';
        } else {
          alert('Please enter a domain name');
        }
      });
    }

    // Enter key handlers
    const whitelistInput = $('#new-whitelist-domain');
    if (whitelistInput) {
      whitelistInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') $('#add-whitelist')?.click();
      });
    }

    const suspiciousInput = $('#new-suspicious-domain');
    if (suspiciousInput) {
      suspiciousInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') $('#add-suspicious')?.click();
      });
    }
  }

  function manageDomain(listType, actionType, domain, domainElement = null, button = null) {
    const ajaxAction = listType === 'whitelist' ? 'whitelist_domain' : 'manage_suspicious_domains';

    ajax({
      url: spamDetective.ajaxUrl,
      data: {
        action: ajaxAction,
        action_type: actionType,
        domain: domain,
        nonce: spamDetective.nonce
      },
      success: function(response) {
        if (response.success) {
          if (actionType === 'remove' && domainElement) {
            fadeOut(domainElement, 300, () => domainElement.remove());
          } else if (actionType === 'add') {
            updateDomainList(listType, domain);
            setTimeout(() => refreshDomainSection(listType), 500);
          }

          if (response.data?.cache_cleared && suspiciousUsers.length > 0) {
            autoReAnalyze(domain, listType, actionType);
          }
        } else {
          if (domainElement) domainElement.style.opacity = '1';
          alert('Error managing domain: ' + response.data);
        }

        if (button && actionType === 'add') {
          button.disabled = false;
          button.textContent = 'Add';
        }
      },
      error: function() {
        if (domainElement) domainElement.style.opacity = '1';
        if (button && actionType === 'add') {
          button.disabled = false;
          button.textContent = 'Add';
        }
        alert('An error occurred while managing the domain. Please try again.');
      }
    });
  }

  function updateDomainList(listType, domain) {
    const containerId = listType === 'whitelist' ? '#whitelisted-domains' : '#suspicious-domains';
    const tagClass = listType === 'whitelist' ? 'whitelist-tag' : 'suspicious-tag';
    const container = $(containerId);

    if (!container) return;

    // Check if domain already exists
    let exists = false;
    container.querySelectorAll('.domain-tag').forEach(tag => {
      const existingDomain = tag.textContent.replace('×', '').trim().toLowerCase();
      if (existingDomain === domain.toLowerCase()) exists = true;
    });

    if (!exists) {
      const tagHtml = `<span class="domain-tag ${tagClass}">${escapeHtml(domain)} <button class="remove-domain" data-domain="${escapeHtml(domain.toLowerCase())}" data-type="${listType}">×</button></span>`;
      const newTag = document.createElement('span');
      newTag.innerHTML = tagHtml;
      const tag = newTag.firstElementChild;
      tag.style.opacity = '0';
      container.appendChild(tag);
      requestAnimationFrame(() => {
        tag.style.transition = 'opacity 300ms ease';
        tag.style.opacity = '1';
      });
    }
  }

  function refreshDomainSection(listType) {
    ajax({
      url: spamDetective.ajaxUrl,
      data: {
        action: 'get_domain_list',
        list_type: listType,
        nonce: spamDetective.nonce
      },
      success: function(response) {
        if (response.success && response.data) {
          renderDomainList(listType, response.data);
        }
      }
    });
  }

  function renderDomainList(listType, domains) {
    const containerId = listType === 'whitelist' ? '#whitelisted-domains' : '#suspicious-domains';
    const tagClass = listType === 'whitelist' ? 'whitelist-tag' : 'suspicious-tag';
    const container = $(containerId);

    if (!container) return;

    container.innerHTML = '';

    domains.forEach(domain => {
      const tagHtml = `<span class="domain-tag ${tagClass}">${escapeHtml(domain)} <button class="remove-domain" data-domain="${escapeHtml(domain.toLowerCase())}" data-type="${listType}">×</button></span>`;
      container.insertAdjacentHTML('beforeend', tagHtml);
    });
  }

  // =============================================
  // Auto Re-Analysis
  // =============================================

  function autoReAnalyze(changedDomain, listType, actionType) {
    if (suspiciousUsers.length === 0) return;

    showReAnalysisProgress(`Re-analyzing users after ${actionType === 'add' ? 'adding' : 'removing'} domain...`);

    const userIds = suspiciousUsers.map(user => user.id);

    ajax({
      url: spamDetective.ajaxUrl,
      data: {
        action: 'reanalyze_users',
        user_ids: userIds,
        nonce: spamDetective.nonce
      },
      success: function(response) {
        hideReAnalysisProgress();

        if (response.success) {
          const updatedUsers = response.data.users;
          const removedCount = response.data.removed_count || 0;

          suspiciousUsers = updatedUsers;
          displayResults();

          if (removedCount > 0) {
            showTemporaryMessage(`Re-analysis complete! ${removedCount} user(s) are no longer flagged as suspicious due to the domain change.`, 'success');
          } else {
            showTemporaryMessage('Re-analysis complete! All users remain flagged as suspicious.', 'info');
          }
        } else {
          showTemporaryMessage('Re-analysis failed: ' + response.data, 'error');
        }
      },
      error: function() {
        hideReAnalysisProgress();
        showTemporaryMessage('Re-analysis failed. Please manually refresh the analysis.', 'error');
      }
    });
  }

  let progressInterval = null;

  function showReAnalysisProgress(message) {
    let indicator = $('#reanalysis-progress');

    if (!indicator) {
      indicator = document.createElement('div');
      indicator.id = 'reanalysis-progress';
      indicator.className = 'reanalysis-progress';
      indicator.innerHTML = '<p></p><div class="progress-bar"><div class="progress-fill"></div></div>';
      const resultsHeader = $('#results-container h2');
      if (resultsHeader) resultsHeader.after(indicator);
    }

    indicator.querySelector('p').textContent = message;
    show(indicator);

    const progressFill = indicator.querySelector('.progress-fill');
    progressFill.style.width = '0%';

    let progress = 0;
    progressInterval = setInterval(() => {
      progress += Math.random() * 10;
      if (progress > 90) progress = 90;
      progressFill.style.width = progress + '%';
      if (progress >= 90) clearInterval(progressInterval);
    }, 100);
  }

  function hideReAnalysisProgress() {
    const indicator = $('#reanalysis-progress');
    if (!indicator) return;

    if (progressInterval) clearInterval(progressInterval);

    const progressFill = indicator.querySelector('.progress-fill');
    progressFill.style.width = '100%';

    setTimeout(() => fadeOut(indicator, 300), 500);
  }

  function showTemporaryMessage(message, type = 'info') {
    const container = $('#results-container');
    if (!container) return;

    const messageEl = document.createElement('div');
    messageEl.className = `temporary-message ${type}`;
    messageEl.innerHTML = `<p>${escapeHtml(message)}</p>`;
    container.prepend(messageEl);

    setTimeout(() => fadeOut(messageEl, 300, () => messageEl.remove()), 5000);

    messageEl.addEventListener('click', () => {
      fadeOut(messageEl, 300, () => messageEl.remove());
    });
  }

  // =============================================
  // Initialize
  // =============================================

  function init() {
    initDetectionSettings();
    initAnalysis();
    initCheckboxHandling();
    initDeleteHandling();
    initExportHandling();
    initDomainManagement();
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
