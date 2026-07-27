import assert from 'node:assert/strict'
import test from 'node:test'

import { SafeAuthError } from '../dist/internal-auth/errors.js'
import { toolError } from '../dist/tools/shared.js'

test('ticket conflicts tell the MCP caller to refetch instead of reporting authentication failure', () => {
  const result = toolError(new SafeAuthError('conflict', {
    correlationId: '11111111-1111-4111-8111-111111111111',
    status: 409,
  }))

  assert.deepEqual(result, {
    isError: true,
    content: [{
      type: 'text',
      text: 'Error: Ticket changed since it was last read. Fetch it again and retry. (reference: 11111111-1111-4111-8111-111111111111)',
    }],
  })
  assert.equal(result.content[0].text.includes('authentication failed'), false)
})
