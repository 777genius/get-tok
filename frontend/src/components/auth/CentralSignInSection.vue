<template>
  <div v-if="configuration?.enabled || failed" class="space-y-3">
    <template v-if="configuration?.enabled">
      <button
        v-for="provider in entries"
        :key="provider.id"
        type="button"
        class="btn btn-secondary w-full"
        :disabled="disabled"
        @click="emit('start', provider.id || undefined)"
      >
        {{
          t(intent === 'register' ? 'auth.central.register' : 'auth.central.signIn', {
            provider: provider.label,
          })
        }}
      </button>
    </template>
    <div v-else role="status" class="space-y-2 text-sm text-gray-500 dark:text-dark-400">
      <p>{{ t('auth.central.unavailable') }}</p>
      <button type="button" class="btn btn-secondary w-full" :disabled="loading" @click="load">
        {{ t('auth.central.retry') }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { centralAuthAPI, type CentralConfiguration } from '@/api/centralAuth'

// CentralSignInSection.vue presents the providers advertised by the central login
// backend and emits the user's selection to the parent form. The parent owns consent,
// captcha, registration intent, and navigation. Configuration failure offers a retry
// without inventing a provider or silently selecting a different authentication method.

// Props keep the form's busy and consent state authoritative for every provider.
// The intent changes only presentation; the parent supplies the actual start request.
withDefaults(
  defineProps<{
    disabled?: boolean // Parent authentication action gate.
    intent?: 'login' | 'register' // Parent account operation intent.
  }>(),
  { intent: 'login' },
)
const emit = defineEmits<{
  start: [provider: string | undefined] // Advertised provider selection event.
}>()

// Configuration and transient loading state belong to this mounted entry section.
// Authentication state remains entirely in the session store and backend cookie.
const { t } = useI18n() // Authentication message translation resolver.
const configuration = ref<CentralConfiguration | null>(null) // Advertised central login settings.
const loading = ref(false) // Configuration request progress flag.
const failed = ref(false) // Retriable configuration failure flag.
const entries = computed(() =>
  configuration.value?.providers.length
    ? configuration.value.providers
    : [{ id: '', label: configuration.value?.provider_name || t('auth.central.defaultProvider') }],
)

// load reads current central login configuration and publishes only advertised entries.
// A missing endpoint represents an older or disabled deployment. Other failures retain
// a visible retry action, and concurrent clicks share the existing loading boundary.
async function load(): Promise<void> {
  if (loading.value) return
  loading.value = true
  failed.value = false
  try {
    configuration.value = await centralAuthAPI.configuration()
  } catch (error) {
    configuration.value = null
    failed.value = (error as { status?: number }).status !== 404
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
