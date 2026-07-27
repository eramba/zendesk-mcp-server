import assert from 'node:assert/strict'
import test from 'node:test'

import { ZendeskClient } from '../dist/zendesk-client.js'

function response(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function queuedClient(bodies) {
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
      fetch: async (input, init = {}) => {
        requests.push({
          url: String(input),
          method: init.method ?? 'GET',
          body: init.body,
        })
        const body = bodies.shift()
        assert.notEqual(body, undefined, 'unexpected Zendesk API request')
        return response(body)
      },
    }),
  }
}

test('ticket normalization retains the approved support context and excludes unknown fields', async () => {
  const { client } = queuedClient([{
    ticket: {
      id: 36870,
      subject: 'Printer is on fire',
      description: 'Smoke everywhere',
      status: 'open',
      priority: 'urgent',
      type: 'incident',
      created_at: '2026-07-26T10:00:00Z',
      updated_at: '2026-07-27T10:00:00Z',
      requester_id: 101,
      submitter_id: 102,
      assignee_id: 103,
      organization_id: 202,
      group_id: 73,
      brand_id: 74,
      ticket_form_id: 75,
      custom_status_id: 76,
      custom_fields: [{ id: 9001, value: ['gold', 'priority'] }],
      collaborator_ids: [104, 105],
      email_cc_ids: [106],
      follower_ids: [107],
      problem_id: 36700,
      due_at: '2026-07-28T10:00:00Z',
      external_id: 'crm-42',
      recipient: 'support@example.test',
      has_incidents: true,
      allow_attachments: true,
      satisfaction_rating: { id: 5, score: 'good', comment: 'Fast' },
      via: { channel: 'email', source: { from: { address: 'hidden@example.test' } } },
      tags: ['printer', 'urgent'],
      upstream_secret: 'must-not-leak',
    },
  }])

  const ticket = await client.getTicket(36870)

  assert.equal(ticket.group_id, 73)
  assert.equal(ticket.ticket_form_id, 75)
  assert.equal(ticket.custom_status_id, 76)
  assert.deepEqual(ticket.custom_fields, [{ id: 9001, value: ['gold', 'priority'] }])
  assert.deepEqual(ticket.collaborator_ids, [104, 105])
  assert.deepEqual(ticket.email_cc_ids, [106])
  assert.deepEqual(ticket.follower_ids, [107])
  assert.deepEqual(ticket.satisfaction_rating, { id: 5, score: 'good', comment: 'Fast' })
  assert.deepEqual(ticket.via, { channel: 'email' })
  assert.equal('upstream_secret' in ticket, false)
})

test('ticket normalization supplies stable defaults for absent rich fields', async () => {
  const { client } = queuedClient([{ ticket: { id: 1 } }])
  const ticket = await client.getTicket(1)

  assert.equal(ticket.group_id, null)
  assert.equal(ticket.ticket_form_id, null)
  assert.deepEqual(ticket.custom_fields, [])
  assert.deepEqual(ticket.collaborator_ids, [])
  assert.equal(ticket.satisfaction_rating, null)
  assert.equal(ticket.via, null)
})

test('user and organization normalization retains curated support context only', async () => {
  const { client } = queuedClient([
    {
      user: {
        id: 101,
        name: 'Requester',
        email: 'requester@example.test',
        alias: 'R',
        phone: '+421900000000',
        verified: true,
        role: 'end-user',
        role_type: 0,
        custom_role_id: null,
        default_group_id: null,
        locale: 'sk',
        locale_id: 42,
        time_zone: 'Bratislava',
        external_id: 'crm-user-101',
        tags: ['enterprise'],
        user_fields: { support_tier: 'gold' },
        last_login_at: '2026-07-27T08:00:00Z',
        organization_id: 202,
        suspended: false,
        active: true,
        upstream_secret: 'must-not-leak',
      },
    },
    {
      results: [{
        result_type: 'organization',
        id: 202,
        name: 'Acme',
        details: 'Enterprise customer',
        notes: '24x7',
        domain_names: ['example.test'],
        external_id: 'crm-org-202',
        group_id: 73,
        organization_fields: { renewal: '2027-01-01' },
        shared_comments: true,
        shared_tickets: true,
        tags: ['enterprise'],
        upstream_secret: 'must-not-leak',
      }],
      next_page: null,
      previous_page: null,
    },
  ])

  const user = await client.getCurrentUser()
  const organization = (await client.searchOrganizations({
    query: 'Acme',
    page: 1,
    perPage: 25,
    sortBy: 'created_at',
    sortOrder: 'desc',
  })).organizations[0]

  assert.equal(user.alias, 'R')
  assert.equal(user.verified, true)
  assert.deepEqual(user.user_fields, { support_tier: 'gold' })
  assert.equal('upstream_secret' in user, false)
  assert.deepEqual(organization.domain_names, ['example.test'])
  assert.deepEqual(organization.organization_fields, { renewal: '2027-01-01' })
  assert.equal(organization.shared_comments, true)
  assert.equal('upstream_secret' in organization, false)
})
