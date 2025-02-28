def update_tables():
    from app import app, db, Trophy  # import here to avoid circular import error
    trophies_data = [
      { "level": 1, "name": "Beginner Badge", "icon": "🥉" },
      { "level": 3, "name": "Rookie Medal", "icon": "🥈" },
      { "level": 5, "name": "Apprentice Trophy", "icon": "🏆" },
      { "level": 8, "name": "Skilled Warrior", "icon": "⚔️" },
      { "level": 12, "name": "Master Explorer", "icon": "🗺️" },
      { "level": 15, "name": "Elite Strategist", "icon": "♟️" },
      { "level": 18, "name": "Champion Cup", "icon": "🏅" },
      { "level": 22, "name": "Grandmaster", "icon": "👑" },
      { "level": 26, "name": "Legendary Hero", "icon": "🔥" },
      { "level": 30, "name": "Immortal", "icon": "💀" },
      { "level": 35, "name": "Speedy", "icon": "⚡" },
      { "level": 40, "name": "Ultimate Conqueror", "icon": "🌟" },
      { "level": 45, "name": "Mythical Warrior", "icon": "🐉" },
      { "level": 50, "name": "Unstoppable", "icon": "🦾" },
      { "level": 55, "name": "Mastermind", "icon": "🧠" },
      { "level": 60, "name": "Dimensional Traveler", "icon": "🚀" },
      { "level": 65, "name": "Void Walker", "icon": "🌌" },
      { "level": 70, "name": "Infinity Breaker", "icon": "♾️" },
      { "level": 75, "name": "Omnipotent", "icon": "🔱" },
      { "level": 80, "name": "Beyond Reality", "icon": "🌀" },
      { "level": 85, "name": "Galactic Ruler", "icon": "🌠" },
      { "level": 90, "name": "Cosmic Guardian", "icon": "🌌" },
      { "level": 95, "name": "Eternal Champion", "icon": "🏅" },
      { "level": 100, "name": "Supreme Deity", "icon": "👑" },
      { "level": 105, "name": "Celestial Knight", "icon": "🌟" },
      { "level": 110, "name": "Astral Commander", "icon": "🚀" },
      { "level": 115, "name": "Quantum Master", "icon": "⚛️" },
      { "level": 120, "name": "Stellar Conqueror", "icon": "🌠" },
      { "level": 125, "name": "Nebula Navigator", "icon": "🌌" },
      { "level": 130, "name": "Galactic Emperor", "icon": "👑" },
      { "level": 135, "name": "Cosmic Overlord", "icon": "🌌" },
      { "level": 140, "name": "Universal Ruler", "icon": "🌌" },
      { "level": 145, "name": "Eternal Sovereign", "icon": "👑" },
      { "level": 150, "name": "Infinite Monarch", "icon": "♾️" },
      { "level": 155, "name": "Timeless Titan", "icon": "⏳" },
      { "level": 160, "name": "Immortal Legend", "icon": "🔥" },
      { "level": 165, "name": "Supreme Overlord", "icon": "👑" },
      { "level": 170, "name": "Omniscient Sage", "icon": "🧙" },
      { "level": 175, "name": "Transcendent Being", "icon": "🌌" },
      { "level": 180, "name": "Infinite Sage", "icon": "♾️" },
      { "level": 185, "name": "Eternal Guardian", "icon": "🛡️" },
      { "level": 190, "name": "Cosmic Sage", "icon": "🌌" },
      { "level": 195, "name": "Galactic Sage", "icon": "🌌" },
      { "level": 200, "name": "Supreme Sage", "icon": "👑" }
    ]

    with app.app_context():
        for t in trophies_data:
            trophy = Trophy.query.filter_by(level=t["level"]).first()
            if not trophy:
                trophy = Trophy(level=t["level"], name=t["name"], icon=t["icon"])
                db.session.add(trophy)
        db.session.commit()
