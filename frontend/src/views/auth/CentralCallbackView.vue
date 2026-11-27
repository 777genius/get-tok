<template>
  <AuthLayout>
    <div class="space-y-6 text-center">
      <h2 class="text-2xl font-bold text-gray-900 dark:text-white">
        {{ t('auth.central.callbackTitle') }}
      </h2>
      <p role="status" class="text-sm text-gray-500 dark:text-dark-400">
        {{ errorKey ? t(`auth.central.errors.${errorKey}`) : t('auth.central.completing') }}
      </p>
      <div v-if="errorKey" class="space-y-3">
        <router-link to="/login" class="btn btn-primary w-full">
          {{ t('auth.central.returnToLogin') }}
        </router-link>
        <router-link
          v-if="errorKey === 'account_not_linked'"
          to="/register"
          class="btn btn-secondary w-full"
        >
          {{ t('auth.createAccount') }}
        </router-link>
      </div>
    </div>
  </AuthLayout>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import AuthLayout from '@/components/layout/AuthLayout.vue'
import { useAuthStore } from '@/stores/auth'

// CentralCallbackView.vue completes navigation after the backend has consumed the
// authorization code and installed its HttpOnly session cookie. The URL may carry
// only a fixed error code; credentials, provider responses, and arbitrary redirect
// destinations are never accepted or reflected by this view.
//
// Session restoration asks the backend for product identity and memory-only CSRF
// material before navigation enters a protected page. The store owns generation
// checks, expiration, and publication, so a late callback cannot restore an earlier
// session after a competing login or logout. Failure leaves account creation and
// existing-account login as explicit choices rather than inferring a merge from email.

// Callback errors are bounded identifiers shared with the backend redirect contract.
const allowedErrors = [
  'account_not_linked',
  'account_conflict',
  'temporarily_unavailable',
  'access_denied',
  'authentication_failed',
] as const
type CallbackError = (typeof allowedErrors)[number] // Fixed callback failure category.

// Route input is consumed once during completion, while the error ref controls the
// visible recovery options. No callback material is persisted in browser storage.
const route = useRoute() // Current callback navigation inputs.
const router = useRouter() // Protected destination navigation owner.
const auth = useAuthStore() // Browser authentication session owner.
const { t } = useI18n() // Authentication message translation resolver.
let active = true // Mounted callback navigation ownership.
const errorKey = ref<CallbackError | null>(null) // Bounded visible failure category.

// showFailure publishes a bounded error and preserves its reload-safe recovery route.
// Only allowlisted identifiers reach this helper. Replacing the complete query and
// fragment removes unexpected input without converting a failed callback into success.
function showFailure(error: CallbackError): void {
  errorKey.value = error
  window.history.replaceState(
    window.history.state,
    '',
    `${window.location.pathname}?error=${error}`,
  )
}

// complete restores a server-confirmed session or displays a fixed recovery message.
// It accepts either no query or one allowlisted error string, rejecting empty,
// repeated, unexpected, or fragment input before any asynchronous request. Failures
// retain only their bounded error in history so a reload cannot restore an unrelated
// cookie and hide the failed flow. Successful completion uses only the product-owned
// role for the dashboard destination; callers cannot supply a redirect URL here.
async function complete(): Promise<void> {
  const reported = route.query.error
  const unexpected = Object.keys(route.query).some((key) => key !== 'error') || Boolean(route.hash)
  if (Object.keys(route.query).length > 0 || unexpected) {
    showFailure(
      !unexpected &&
        typeof reported === 'string' &&
        allowedErrors.some((value) => value === reported)
        ? (reported as CallbackError)
        : 'authentication_failed',
    )
    return
  }
  window.history.replaceState(window.history.state, '', window.location.pathname)
  try {
    await auth.restoreCentralSession()
    if (active) await router.replace(auth.isAdmin ? '/admin/dashboard' : '/dashboard')
  } catch (error) {
    const status = (error as { status?: number }).status
    if (active) {
      showFailure(
        status === 0 || (status !== undefined && status >= 500)
          ? 'temporarily_unavailable'
          : 'authentication_failed',
      )
    }
  }
}

onMounted(complete)
onUnmounted(() => {
  active = false
})
</script>
