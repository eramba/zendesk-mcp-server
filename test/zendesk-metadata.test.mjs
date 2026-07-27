import assert from 'node:assert/strict'
import test from 'node:test'

import { ZendeskClient } from '../dist/zendesk-client.js'

function metadataClient(bodies) {
  const requests = []
  return {
    requests,
    client: new ZendeskClient({
      subdomain: 'acme',
      auth: {
        kind: 'oauth',
        accessToken: 'access-token-sentinel',
        onUnauthorized: async () => assert.fail('fresh token must not refresh'),
      },
      fetch: async (input) => {
        requests.push(String(input))
        const body = bodies.shift()
        assert.notEqual(body, undefined, 'unexpected Zendesk request')
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      },
    }),
  }
}

test('metadata methods normalize metrics, cursor forms, and active custom statuses', async () => {
  const { client, requests } = metadataClient([
    {
      ticket_metric: {
        id: 901,
        ticket_id: 36870,
        assigned_at: '2026-07-27T09:00:00Z',
        solved_at: null,
        replies: 3,
        reopens: 1,
        reply_time_in_minutes: { calendar: 30, business: 12 },
        requester_wait_time_in_minutes: { calendar: 50, business: 20 },
        agent_wait_time_in_minutes: { calendar: 10, business: 5 },
        full_resolution_time_in_minutes: { calendar: 80, business: 40 },
      },
    },
    {
      ticket_forms: [{
        id: 75,
        name: 'Incident',
        display_name: 'Report incident',
        active: true,
        default: true,
        position: 1,
        ticket_field_ids: [1, 2, 9001],
      }],
      meta: { has_more: false },
      links: { next: null },
    },
    {
      custom_statuses: [{
        id: 76,
        active: true,
        default: false,
        agent_label: 'Investigating',
        end_user_label: 'We are investigating',
        description: 'Agent is working',
        end_user_description: 'We are working on your issue',
        status_category: 'open',
      }],
    },
  ])

  const metrics = await client.getTicketMetrics(36870)
  const forms = await client.listTicketForms({ pageSize: 25 })
  const statuses = await client.listCustomStatuses()

  assert.deepEqual(requests, [
    'https://acme.zendesk.com/api/v2/tickets/36870/metrics.json',
    'https://acme.zendesk.com/api/v2/ticket_forms.json?active=true&page%5Bsize%5D=25',
    'https://acme.zendesk.com/api/v2/custom_statuses.json?active=true',
  ])
  assert.deepEqual(metrics.reply_time_in_minutes, { calendar: 30, business: 12 })
  assert.equal(metrics.solved_at, null)
  assert.deepEqual(forms.items[0].ticket_field_ids, [1, 2, 9001])
  assert.equal(forms.items[0].default, true)
  assert.deepEqual(statuses, {
    statuses: [{
      id: 76,
      active: true,
      default: false,
      agent_label: 'Investigating',
      end_user_label: 'We are investigating',
      description: 'Agent is working',
      end_user_description: 'We are working on your issue',
      status_category: 'open',
      created_at: null,
      updated_at: null,
    }],
    count: 1,
  })
})
