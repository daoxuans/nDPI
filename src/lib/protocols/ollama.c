/*
 * ollama.c
 *
 * Copyright (C) 2026 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_OLLAMA

#include "ndpi_api.h"
#include "ndpi_private.h"

/* Ollama - local LLM inference server
   Default port: 11434
   HTTP REST API with distinctive endpoints:
   - GET / → "Ollama is running" (plain text, unique fingerprint)
   - GET /api/version → {"version":"0.x.x"}
   - POST /api/chat, POST /api/generate */

static void ndpi_search_ollama(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const char *payload_str = (const char *)packet->payload;
  u_int16_t payload_len = packet->payload_packet_len;
  int found = 0;

  NDPI_LOG_DBG(ndpi_struct, "search Ollama\n");

  /* Record HTTP method */
  if(payload_len > 4 && memcmp(packet->payload, "GET ", 4) == 0)
    flow->protos.ollama.http_method = 0;
  else if(payload_len > 5 && memcmp(packet->payload, "POST ", 5) == 0)
    flow->protos.ollama.http_method = 1;

  /* Helper: save API action name from path */
  #define SAVE_OLLAMA_ACTION(name, nlen) do { \
    if(nlen < sizeof(flow->protos.ollama.api_action)) { \
      memcpy(flow->protos.ollama.api_action, name, nlen); \
      flow->protos.ollama.api_action[nlen] = '\0'; \
    } \
  } while(0)

  /* Helper: try to extract model name from JSON payload */
  #define EXTRACT_OLLAMA_MODEL() do { \
    if(payload_len > 10) { \
      const char *m = ndpi_strnstr(payload_str, "\"model\":\"", payload_len); \
      if(m != NULL) { \
        const char *mv = m + 9; \
        const char *me = ndpi_strnstr(mv, "\"", payload_len - (mv - payload_str)); \
        if(me != NULL) { \
          size_t mlen = me - mv; \
          if(mlen < sizeof(flow->protos.ollama.model_name)) { \
            memcpy(flow->protos.ollama.model_name, mv, mlen); \
            flow->protos.ollama.model_name[mlen] = '\0'; \
          } \
        } \
      } \
    } \
  } while(0)

  /* Case 1: Ollama over HTTP */
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
     flow->detected_protocol_stack[1] == NDPI_PROTOCOL_HTTP) {

    /* Check response body for "Ollama is running" - most distinctive signature */
    if(payload_len >= 17 &&
       ndpi_strnstr(payload_str, "Ollama is running", payload_len) != NULL) {
      NDPI_LOG_INFO(ndpi_struct, "found Ollama (response body)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OLLAMA,
                                 NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
      return;
    }

    /* Check URL path for Ollama-specific /api/ endpoints */
    if(packet->http_url_name.ptr != NULL && packet->http_url_name.len > 0) {
      const char *url = (const char *)packet->http_url_name.ptr;
      u_int16_t url_len = packet->http_url_name.len;

      if(ndpi_strnstr(url, "/api/chat", url_len) != NULL) {
        SAVE_OLLAMA_ACTION("chat", 4); found = 1;
      } else if(ndpi_strnstr(url, "/api/generate", url_len) != NULL) {
        SAVE_OLLAMA_ACTION("generate", 8); found = 1;
      } else if(ndpi_strnstr(url, "/api/tags", url_len) != NULL) {
        SAVE_OLLAMA_ACTION("tags", 4); found = 1;
      } else if(ndpi_strnstr(url, "/api/version", url_len) != NULL) {
        SAVE_OLLAMA_ACTION("version", 7); found = 1;
      } else if(ndpi_strnstr(url, "/api/show", url_len) != NULL) {
        SAVE_OLLAMA_ACTION("show", 4); found = 1;
      } else if(ndpi_strnstr(url, "/api/push", url_len) != NULL) {
        SAVE_OLLAMA_ACTION("push", 4); found = 1;
      } else if(ndpi_strnstr(url, "/api/create", url_len) != NULL) {
        SAVE_OLLAMA_ACTION("create", 6); found = 1;
      } else if(ndpi_strnstr(url, "/api/delete", url_len) != NULL) {
        SAVE_OLLAMA_ACTION("delete", 6); found = 1;
      } else if(ndpi_strnstr(url, "/api/copy", url_len) != NULL) {
        SAVE_OLLAMA_ACTION("copy", 4); found = 1;
      } else if(ndpi_strnstr(url, "/api/ps", url_len) != NULL) {
        SAVE_OLLAMA_ACTION("ps", 2); found = 1;
      }

      if(found) {
        EXTRACT_OLLAMA_MODEL();
        NDPI_LOG_INFO(ndpi_struct, "found Ollama (/api/ URL path)\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OLLAMA,
                                   NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
        return;
      }
    }

    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  /* Case 2: Ollama over raw TCP (port 11434, cleartext HTTP without prior detection) */
  if(packet->tcp != NULL && payload_len > 17) {
    /* Check for "Ollama is running" in response */
    if(ndpi_strnstr(payload_str, "Ollama is running", payload_len) != NULL) {
      NDPI_LOG_INFO(ndpi_struct, "found Ollama (raw TCP)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OLLAMA,
                                 NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }

    /* Check for HTTP request with /api/ path to Ollama */
    if(payload_len > 6 &&
       (memcmp(packet->payload, "GET ", 4) == 0 || memcmp(packet->payload, "POST ", 5) == 0) &&
       ndpi_strnstr(payload_str, "/api/", payload_len) != NULL) {
      /* Try to match the specific action */
      if(ndpi_strnstr(payload_str, "/api/chat", payload_len) != NULL)
        SAVE_OLLAMA_ACTION("chat", 4);
      else if(ndpi_strnstr(payload_str, "/api/generate", payload_len) != NULL)
        SAVE_OLLAMA_ACTION("generate", 8);
      else if(ndpi_strnstr(payload_str, "/api/tags", payload_len) != NULL)
        SAVE_OLLAMA_ACTION("tags", 4);
      else if(ndpi_strnstr(payload_str, "/api/version", payload_len) != NULL)
        SAVE_OLLAMA_ACTION("version", 7);
      else if(ndpi_strnstr(payload_str, "/api/show", payload_len) != NULL)
        SAVE_OLLAMA_ACTION("show", 4);

      EXTRACT_OLLAMA_MODEL();
      NDPI_LOG_INFO(ndpi_struct, "found Ollama (raw TCP request)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OLLAMA,
                                 NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);

  #undef SAVE_OLLAMA_ACTION
  #undef EXTRACT_OLLAMA_MODEL
}

void init_ollama_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Ollama", ndpi_struct,
                     ndpi_search_ollama,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_OLLAMA);
}