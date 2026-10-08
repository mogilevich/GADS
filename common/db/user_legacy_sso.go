/*
 * This file is part of GADS.
 *
 * Copyright (c) 2022-2025 Nikola Shabanov
 *
 * This source code is licensed under the GNU Affero General Public License v3.0.
 * You may obtain a copy of the license at https://www.gnu.org/licenses/agpl-3.0.html
 */

package db

import (
	"GADS/common/models"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

// legacySSOMigration marks in global_settings that the migration below ran
const legacySSOMigration = "legacy-sso-migration"

// MigrateLegacySSOUsers converts users created by the earlier SSO integration
// of this fork, which marked them with a __SSO__ prefix in the password, to
// SSO users without a password. They get bound to their identity on the next
// sign-in. It runs once: afterwards such a prefix is just a password, and a
// local user who picks it must not turn into an SSO user. Fork only
func (m *MongoStore) MigrateLegacySSOUsers() (int64, error) {
	settings := m.GetCollection("global_settings")
	marker := bson.D{{Key: "type", Value: legacySSOMigration}}
	if HasDocuments(m.Ctx, settings, marker) {
		return 0, nil
	}

	coll := m.GetCollection("users")
	filter := bson.M{"password": bson.M{"$regex": "^__SSO__"}}
	update := bson.M{
		"$set":   bson.M{"auth_source": models.AuthSourceOIDC},
		"$unset": bson.M{"password": ""},
	}

	result, err := coll.UpdateMany(m.Ctx, filter, update)
	if err != nil {
		return 0, fmt.Errorf("failed to migrate legacy SSO users: %w", err)
	}

	err = UpsertDocument[models.GlobalSettings](m.Ctx, settings, marker, models.GlobalSettings{
		Type:        legacySSOMigration,
		Settings:    bson.M{"migrated_users": result.ModifiedCount},
		LastUpdated: time.Now(),
	})
	if err != nil {
		return result.ModifiedCount, fmt.Errorf("failed to record the legacy SSO user migration: %w", err)
	}
	return result.ModifiedCount, nil
}
