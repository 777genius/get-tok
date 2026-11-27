import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { replaceAuthentication } from '@/api/authenticationContext'
import {
  createProviderTestRun,
  executeProviderTest,
  type ProviderTestRequestBody,
} from '../providerTestRun'

/**
 * providerTestRun.spec.ts checks image opt-in, immutable preview snapshots, and response
 * cancellation after authentication changes. Local SSE fixtures exercise the real runner
 * without calling a provider; controlled reads distinguish unopened and active response bodies.
 */

beforeEach(() => replaceAuthentication())
afterEach(() => {
  replaceAuthentication()
  vi.unstubAllGlobals()
})

describe('decision image submission', () => {
  // Two runs share an editable image draft and receive nullable-confidence Box answers.
  // Requests explicitly enable images while private preview metadata stays in independent run snapshots.
  it('sends image opt-in and snapshots images for each run', async () => {
    const fetch = vi
      .fn()
      .mockImplementation(
        async () =>
          new Response(
            `data: ${JSON.stringify({ type: 'test_complete', success: true, data: { usage_valid: true, response: { model: 'jev-1.14.0', answers: { target: { type: 'box', box: { top: 0, bottom: 1, left: 0, right: 1 }, confidence: null } }, usage: { input_tokens: 1, output_tokens: 0 } } } })}\n`,
          ),
      )
    vi.stubGlobal('fetch', fetch)
    const body: ProviderTestRequestBody = {
      model_id: 'jev-latest',
      test_type: 'decision',
      systemone: {
        state: '<photo>',
        questions: { target: { type: 'box', instructions: 'Find the mug' } },
        assets: { '<photo>': { type: 'image', format: 'png', data_base64: 'aW1hZ2U=' } },
      },
      decisionPreview: {
        images: { '<photo>': { name: 'original.png', src: 'data:image/png;base64,aW1hZ2U=' } },
        boxImages: { target: '<photo>' },
      },
    }
    const runs = [createProviderTestRun(), createProviderTestRun()]
    for (const run of runs) {
      await executeProviderTest({
        providerId: 1,
        providerName: 'Jev',
        body,
        run,
        signal: new AbortController().signal,
        t: (key) => key,
      })
      expect(run.status).toBe('success')
      expect(run.decisionResult?.answers.target.confidence).toBeNull()
    }
    body.decisionPreview!.images['<photo>'].name = 'changed.png'
    body.systemone!.questions.target.instructions = 'Changed question'
    for (const run of runs) {
      expect(run.decisionPreview?.images['<photo>'].name).toBe('original.png')
      expect(run.decisionQuestions?.target.instructions).toBe('Find the mug')
    }
    for (const [, options] of fetch.mock.calls) {
      expect(options.headers['TypeSafe-Danger-Zone-Images']).toBe('true')
      expect(JSON.parse(options.body)).not.toHaveProperty('decisionPreview')
      expect(JSON.parse(options.body).systemone.assets['<photo>'].data_base64).toBe('aW1hZ2U=')
    }
  })

  // A text-only decision test uses the same runner without opting into image support.
  // The absence of image content does not add an experimental header to ordinary probes.
  it('leaves text-only decisions without image opt-in', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(new Response('data: {"type":"test_complete","success":true}\n'))
    vi.stubGlobal('fetch', fetch)
    await executeProviderTest({
      providerId: 1,
      providerName: 'Jev',
      body: {
        model_id: 'jev-latest',
        test_type: 'decision',
        systemone: {
          state: 'ready',
          questions: { ready: { type: 'noul', instructions: 'Ready?' } },
        },
      },
      run: createProviderTestRun(),
      signal: new AbortController().signal,
      t: (key) => key,
    })
    expect(fetch.mock.calls[0][1].headers).not.toHaveProperty('TypeSafe-Danger-Zone-Images')
  })
})

describe('authentication-owned response cancellation', () => {
  // A response arrives before its body reader is acquired, with unchanged or replaced authentication.
  // Only a replaced session cancels the body; the original session still accepts its terminal event.
  it.each([false, true])(
    'cancels an unopened response only for replacement=%s',
    async (replaced) => {
      const cancel = vi.fn()
      const response = new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(
              new TextEncoder().encode('data: {"type":"test_complete","success":true}\n'),
            )
            if (!replaced) controller.close()
          },
          cancel,
        }),
      )
      vi.stubGlobal(
        'fetch',
        vi.fn(async () => {
          if (replaced) replaceAuthentication()
          return response
        }),
      )
      const run = createProviderTestRun()
      await executeProviderTest({
        providerId: 1,
        providerName: 'Fixture',
        body: { model_id: 'fixture-model', test_type: 'text' },
        run,
        signal: new AbortController().signal,
        t: (key) => key,
      })
      expect(cancel).toHaveBeenCalledTimes(replaced ? 1 : 0)
      expect(run.status).toBe(replaced ? 'error' : 'success')
      expect(run.replyText).toBe('')
    },
  )

  // Authentication changes while the real stream reader waits for its next event.
  // The stale event must remain unpublished and cancellation must release the still-open upstream body.
  it('cancels the reader when authentication changes during a read', async () => {
    const cancel = vi.fn()
    let controller!: ReadableStreamDefaultController<Uint8Array>
    let started!: () => void
    const reading = new Promise<void>((resolve) => {
      started = resolve
    })
    // Demand-driven pulling signals when the runner actually waits in reader.read, so
    // the session change cannot race ahead of acquiring that response's reader.
    const response = new Response(
      new ReadableStream<Uint8Array>(
        {
          start(value) {
            controller = value
          },
          pull() {
            started()
          },
          cancel,
        },
        { highWaterMark: 0 },
      ),
    )
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response))
    const run = createProviderTestRun()
    const completion = executeProviderTest({
      providerId: 1,
      providerName: 'Fixture',
      body: { model_id: 'fixture-model', test_type: 'text' },
      run,
      signal: new AbortController().signal,
      t: (key) => key,
    })
    await reading
    replaceAuthentication()
    controller.enqueue(new TextEncoder().encode('data: {"type":"content","text":"stale"}\n'))
    await completion
    expect(cancel).toHaveBeenCalledTimes(1)
    expect(run.replyText).toBe('')
    expect(run.status).toBe('error')
  })
})
