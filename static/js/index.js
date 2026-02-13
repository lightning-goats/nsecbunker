window.app = Vue.createApp({
  el: '#vue',
  mixins: [windowMixin],
  watch: {
    selectedWallet() {
      this.getKeys()
      this.getPermissions()
      this.getLogs()
    }
  },
  data() {
    return {
      selectedWallet: null,
      keys: [],
      permissions: [],
      logs: [],
      newKeyInput: '',
      showPermDialog: false,
      showEditPermDialog: false,
      permForm: {
        key_id: null,
        extension_id: '',
        kind: null,
        rate_limit_count: null,
        rate_limit_seconds: null
      },
      editPermForm: {
        id: null,
        rate_limit_count: null,
        rate_limit_seconds: null
      },
      keyCols: [
        {
          name: 'pubkey_hex',
          label: 'Public Key',
          field: 'pubkey_hex',
          align: 'left'
        },
        {
          name: 'created_at',
          label: 'Created',
          field: 'created_at',
          align: 'left',
          format: val => new Date(val).toLocaleString()
        },
        {name: 'actions', label: 'Actions', align: 'right'}
      ],
      permCols: [
        {
          name: 'extension_id',
          label: 'Extension',
          field: 'extension_id',
          align: 'left'
        },
        {name: 'kind', label: 'Kind', field: 'kind', align: 'left'},
        {name: 'rate_limit', label: 'Rate Limit', align: 'left'},
        {
          name: 'created_at',
          label: 'Granted',
          field: 'created_at',
          align: 'left',
          format: val => new Date(val).toLocaleString()
        },
        {name: 'actions', label: 'Actions', align: 'right'}
      ],
      logCols: [
        {
          name: 'created_at',
          label: 'Time',
          field: 'created_at',
          align: 'left',
          format: val => new Date(val).toLocaleString()
        },
        {
          name: 'extension_id',
          label: 'Extension',
          field: 'extension_id',
          align: 'left'
        },
        {name: 'kind', label: 'Kind', field: 'kind', align: 'left'},
        {name: 'event_id', label: 'Event ID', align: 'left'}
      ]
    }
  },
  computed: {
    keyOptions() {
      return this.keys.map(k => ({
        label: this.shortKey(k.pubkey_hex),
        value: k.id
      }))
    }
  },
  methods: {
    shortKey(hex) {
      if (!hex) return ''
      return hex.substring(0, 12) + '...' + hex.substring(hex.length - 8)
    },
    copyText(text) {
      navigator.clipboard.writeText(text).then(() => {
        Quasar.Notify.create({message: 'Copied!', timeout: 500})
      })
    },

    // --- Keys ---
    getKeys() {
      LNbits.api
        .request(
          'GET',
          '/nsecbunker/api/v1/keys',
          this.selectedWallet.adminkey
        )
        .then(response => {
          this.keys = response.data
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    importKey() {
      LNbits.api
        .request(
          'POST',
          '/nsecbunker/api/v1/keys',
          this.selectedWallet.adminkey,
          {private_key: this.newKeyInput}
        )
        .then(response => {
          this.newKeyInput = ''
          this.getKeys()
          Quasar.Notify.create({
            message: 'Key imported successfully.',
            timeout: 700
          })
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    generateKey() {
      LNbits.api
        .request(
          'POST',
          '/nsecbunker/api/v1/keys/generate',
          this.selectedWallet.adminkey
        )
        .then(response => {
          this.getKeys()
          Quasar.Notify.create({
            message: 'New key generated.',
            timeout: 700
          })
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    deleteKey(keyId) {
      LNbits.utils
        .confirmDialog(
          'Delete this key? All associated permissions will also be removed.'
        )
        .onOk(() => {
          LNbits.api
            .request(
              'DELETE',
              '/nsecbunker/api/v1/keys/' + keyId,
              this.selectedWallet.adminkey
            )
            .then(() => {
              this.getKeys()
              this.getPermissions()
              Quasar.Notify.create({message: 'Key deleted.', timeout: 700})
            })
            .catch(err => {
              LNbits.utils.notifyApiError(err)
            })
        })
    },

    // --- Permissions ---
    getPermissions() {
      LNbits.api
        .request(
          'GET',
          '/nsecbunker/api/v1/permissions',
          this.selectedWallet.adminkey
        )
        .then(response => {
          this.permissions = response.data
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    createPermission() {
      LNbits.api
        .request(
          'POST',
          '/nsecbunker/api/v1/permissions',
          this.selectedWallet.adminkey,
          this.permForm
        )
        .then(response => {
          this.showPermDialog = false
          this.permForm = {
            key_id: null,
            extension_id: '',
            kind: null,
            rate_limit_count: null,
            rate_limit_seconds: null
          }
          this.getPermissions()
          Quasar.Notify.create({
            message: 'Permission granted.',
            timeout: 700
          })
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    editPermission(perm) {
      this.editPermForm = {
        id: perm.id,
        rate_limit_count: perm.rate_limit_count,
        rate_limit_seconds: perm.rate_limit_seconds
      }
      this.showEditPermDialog = true
    },
    updatePermission() {
      LNbits.api
        .request(
          'PUT',
          '/nsecbunker/api/v1/permissions/' + this.editPermForm.id,
          this.selectedWallet.adminkey,
          {
            rate_limit_count: this.editPermForm.rate_limit_count,
            rate_limit_seconds: this.editPermForm.rate_limit_seconds
          }
        )
        .then(response => {
          this.showEditPermDialog = false
          this.getPermissions()
          Quasar.Notify.create({
            message: 'Permission updated.',
            timeout: 700
          })
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    deletePermission(permId) {
      LNbits.utils.confirmDialog('Revoke this permission?').onOk(() => {
        LNbits.api
          .request(
            'DELETE',
            '/nsecbunker/api/v1/permissions/' + permId,
            this.selectedWallet.adminkey
          )
          .then(() => {
            this.getPermissions()
            Quasar.Notify.create({
              message: 'Permission revoked.',
              timeout: 700
            })
          })
          .catch(err => {
            LNbits.utils.notifyApiError(err)
          })
      })
    },

    // --- Logs ---
    getLogs() {
      LNbits.api
        .request(
          'GET',
          '/nsecbunker/api/v1/log',
          this.selectedWallet.adminkey
        )
        .then(response => {
          this.logs = response.data
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    }
  },
  created() {
    this.selectedWallet = this.g.user.wallets[0]
  }
})
