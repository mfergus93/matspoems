/**
 * Poetry Data Store
 * To add a new poem, simply add an object to this array.
 * 
 * Fields:
 * - id: unique string identifier
 * - title: Title of the poem
 * - date: Publication or composition date (YYYY-MM-DD)
 * - tags: Array of category strings (e.g. ["Nature", "Reflections"])
 * - stanzas: Array of arrays (each outer array is a stanza, inner strings are lines)
 * - excerpt: Short 1-2 line snippet shown when card is collapsed (optional, auto-generated if omitted)
 */

const POEMS_DATA = [
  {
    id: "across-from-a-raven",
    title: "Across from a Raven",
    date: "2026-08-08",
    tags: ["Reflections", "Connection"],
    stanzas: [
      [
        "You can be so sweet.",
        "and be met by the cold."
      ],
      [
        "So playful,",
        "and met by insecurity."
      ],
      [
        "Your confidence,",
        "by jealousy."
      ],
      [
        "Possibility.",
        "fear."
      ],
      [
        "Awake.",
        "sleepwalking."
      ],
      [
        "Across from you,",
        "he is, of course,",
        "a crow?"
      ]
    ],
    excerpt: "You can be so sweet and be met by the cold..."
  },
  {
    id: "the-pout",
    title: "The Pout",
    date: "2026-08-07",
    tags: ["Reflections", "Memory"],
    stanzas: [
      [
        "The Day",
        "had used us up",
        "Yet neither wished it Done"
      ],
      [
        "You spoke no plea",
        "Your Mouth did",
        "though",
        "A tiny mutiny"
      ],
      [
        "Such an extravagant Pout",
        "For one who merely meant",
        "Goodbye"
      ],
      [
        "I knew then",
        "or almost knew"
      ],
      [
        "You wanted",
        "One more Hour."
      ]
    ],
    excerpt: "The Day had used us up yet neither wished it Done..."
  },
  {
    id: "closure",
    title: "House with No Windows",
    date: "2026-07-18",
    tags: ["Reflections", "Memory"],
    stanzas: [
      [
        "I need only to know",
        "that somewhere in your memory",
        "there remains a room",
        "in which you were longing",
        "for me to meet you."
      ],
      [
        "Do not let the door",
        "through which I left badly",
        "become the whole house."
      ],
      [
        "There was another door."
      ],
      [
        "To a room I could not enter,",
        "locked to me",
        "I could not find",
        "The Key"
      ],
      [
        "There was laughter there."
      ],
      [
        "There was tenderness there."
      ],
      [
        "You lived there"
      ],
      [
        "If only I lived there too"
      ],
      [
        "I am waiting but there are no windows."
      ],
      [
        "Do I knock?"
      ]
    ],
    excerpt: "I need only to know that somewhere in your memory..."
  },
  {
    id: "that-cat-is-just-not-right",
    title: "That Cat Is Just Not Right",
    date: "2025-11-10",
    tags: ["Humor", "Reflections"],
    stanzas: [
      [
        "He meows at you.",
        "Meow."
      ],
      [
        "You are seated.",
        "Meow. Meow."
      ],
      [
        "You are standing.",
        "Meow. Meow. Mewo."
      ],
      [
        "You are walking.",
        "Meow. Meow. Mowe. Meow."
      ],
      [
        "You are gone,",
        ""
      ],
      [
        "You have returned.",
        "Meow. Meow. Mewo meow. Mowe. Meow meow."
      ],
      [
        "You left food.",
        "Meow. Meow. Mewo meow. Meow meow. Mrow. Meow."
      ],
      [
        "You didn’t leave food.",
        "Meow. Meow meow. Mewo. Meow meow. Moweo. Meow. Mrow."
      ],
      [
        "You are sleeping.",
        "Meow. Mewo. Meow meow. Mroweo. Meoaow meow. Mewo. Mow. Meow meow. Mrow."
      ],
      [
        "You are awake.",
        "Meow. Meow mewo. Mrow. Mowe meow. Meoaow. Meow meow. Mewo. Moweo meow. Mrow. Meow."
      ],
      [
        "You closed the door.",
        "Meow. Meow. Mewo. Mroweo. Meow meow meow. Mowe. Mroaw. Mewo meow. Meow meow. Moweo. Meow."
      ],
      [
        "You opened the door.",
        "Meow. Mewo. Meow meow. Mroweo moweo meow. Meoaow. Meow mewo. Mrow meow meow. Mowe. Meow. Meow meow."
      ],
      [
        "You pet him.",
        "Meow meow. Mewo. Mrow. Meoaow meow. Mowe mewo. Meow meow. Mroweo. Meow meow meow. Moweo. Mrow. Meow."
      ],
      [
        "You stopped petting him.",
        "Meow. Meow. Mewo? MROWE. Meoaow. Mewo meow. Mroweo. Meow meow. Mowe meow. Mewo. Meow meow. Mrow. Meoaow."
      ],
      [
        "You have done nothing.",
        "Meow. Mewo. Mow. Meoaow. Mroweo. Meow meow. Mewo mrow. Meow. Moweo. Meow meow. Meoaow. Mrow. Mewo. Meow. Meow."
      ],
      [
        "You might do something.",
        "Meow meow. Mewo mrow. Mowe. Meoaow. Meow mewo. Mroweo. Moweo. Meow meow meow. Mrow. Mewo. Meoaow. Meow meow. Mowe. Meow. Meow."
      ],
      [
        "You once did something.",
        "Meow. Mewo. Mroweo. Meoaow. Mowe meow meow. Mrow. Mewo. Meoaow. Moweo. Meow meow. Mroweo. Meow mewo. Mrow. Meow. Mewo. Meow meow."
      ],
      [
        "You have done something he remembers.",
        "Meow meow mewo. Mroweo. Mowe. Meoaow meow. Mrow mrow. Mewo meow. Moweo. Meoaow. Meow meow. Mewo. Mroweo. Meow meow. Mowe. Meow. Mrow. Mewo. Meow."
      ],
      [
        "You have done something he has forgotten.",
        "Meow. Mewo. Mowe. Mroweo. Meoaow. Mrow. Mewo meow meow. Moweo. Meow. Meoaow. Mroweo. Mewo. Meow mrow. Meow meow. Meow. Mowe. Mroweo. Meoaow. Meow."
      ],
      [
        "And still",
        "he looks at you",
        "with the grave expression",
        "of a creature",
        "who has been trying",
        "for years",
        "to explain something important.",
        "Meow. Meow mewo meow. Mroweo. Mowe mowe. Meoaow mewo meow mrow. Moweo. Meow meow. Mroweo. Mewo meoaow. Mrow. Meow meow. Moweo. Meow mewo. Mroweo. Meow meow. Meoaow. Mrow. Mewo. Meow. Meow meow."
      ],
      [
        "You look back at him. You still don't know what he wants.",
        "You meow."
      ],
      [
        "There is no escape."
      ],
      [
        "The cat is just not right."
      ]
    ],
    excerpt: "He meows at you. Meow. You walk away..."
  }
];

/**
 * Favorite Classic Poems Store
 * Embedded directly for in-feed reading and collapse/expand.
 */
const FAVORITES_DATA = [
  {
    id: "invictus",
    title: "Invictus",
    author: "William Ernest Henley",
    date: "1875",
    tags: ["Favorites", "Resilience"],
    stanzas: [
      [
        "Out of the night that covers me,",
        "Black as the pit from pole to pole,",
        "I thank whatever gods may be",
        "For my unconquerable soul."
      ],
      [
        "In the fell clutch of circumstance",
        "I have not winced nor cried aloud.",
        "Under the bludgeonings of chance",
        "My head is bloody, but unbowed."
      ],
      [
        "Beyond this place of wrath and tears",
        "Loom but the Horror of the shade,",
        "And yet the menace of the years",
        "Finds and shall find me unafraid."
      ],
      [
        "It matters not how strait the gate,",
        "How charged with punishments the scroll,",
        "I am the master of my fate,",
        "I am the captain of my soul."
      ]
    ],
    excerpt: "Out of the night that covers me, black as the pit from pole to pole..."
  },
  {
    id: "she-walks-in-beauty",
    title: "She Walks in Beauty",
    author: "Lord Byron",
    date: "1814",
    tags: ["Favorites", "Beauty"],
    stanzas: [
      [
        "She walks in beauty, like the night",
        "Of cloudless climes and starry skies;",
        "And all that’s best of dark and bright",
        "Meet in her aspect and her eyes;",
        "Thus mellowed to that tender light",
        "Which heaven to gaudy day denies."
      ],
      [
        "One shade the more, one ray the less,",
        "Had half impaired the nameless grace",
        "Which waves in every raven tress,",
        "Or softly lightens o’er her face;",
        "Where thoughts serenely sweet express,",
        "How pure, how dear their dwelling-place."
      ],
      [
        "And on that cheek, and o’er that brow,",
        "So soft, so calm, yet eloquent,",
        "The smiles that win, the tints that glow,",
        "But tell of days in goodness spent,",
        "A mind at peace with all below,",
        "A heart whose love is innocent!"
      ]
    ],
    excerpt: "She walks in beauty, like the night..."
  },
  {
    id: "time-does-not-bring-relief",
    title: "Time does not bring relief; you all have lied",
    author: "Edna St. Vincent Millay",
    date: "1917",
    tags: ["Favorites", "Grief", "Memory"],
    stanzas: [
      [
        "Time does not bring relief; you all have lied",
        "Who told me time would ease me of my pain!",
        "I miss him in the weeping of the rain;",
        "I miss him when the sun is on the snow;",
        "Attributes of the place where he would go",
        "There do I find him still; and at the tide",
        "Of the full moon I see him. All the year,",
        "All the year through, there’s not a place I can go",
        "Where he is not!—And so with sorrowing eyes",
        "I look upon the place where once he stood,",
        "And say, “There is no sound here,”—until I",
        "Remember how he spoke, and with what tone,",
        "And then the room is filled with sound alone,",
        "And I am left with silence."
      ]
    ],
    excerpt: "Time does not bring relief; you all have lied who told me time would ease me..."
  },
  {
    id: "sapphos-fragments",
    title: "Fragments",
    author: "Sappho",
    date: "c. 600 BCE",
    tags: ["Favorites", "Love", "Classics"],
    stanzas: [
      [
        "I. Fragment 31",
        "",
        "He seems to me equal to the gods, that man",
        "who sits beside you and listens close to your",
        "sweet speaking and lovely laughing...",
        "My tongue breaks, a subtle fire runs under my skin,",
        "my eyes see nothing, my ears ring,",
        "and cold sweat covers me."
      ],
      [
        "II. Fragment 1 (Ode to Aphrodite)",
        "",
        "Deathless Aphrodite of the throned posture,",
        "weaver of wiles, child of Zeus, I beg you:",
        "do not crush my heart with anguish...",
        "If she flees now, soon she will follow;",
        "if she refuses gifts, soon she will give them;",
        "if she does not love now, soon she will love."
      ],
      [
        "III. Fragment 16",
        "",
        "Some say an army of horsemen, some of foot soldiers,",
        "some of ships is the most beautiful thing on the dark earth,",
        "but I say it is whatever one loves."
      ],
      [
        "IV. Fragment 94",
        "",
        "Honestly I wish I were dead.",
        "She left me weeping many tears and said,",
        "“Ah Sappho, how terribly we suffer...”",
        "And I answered, “Go and be happy, but remember me...”"
      ],
      [
        "V. Fragment 47 & 48",
        "",
        "Love shook my heart",
        "like a mountain wind falling on oak trees.",
        "You came, and I was longing for you;",
        "you cooled my heart which was burning with desire."
      ]
    ],
    excerpt: "He seems to me equal to the gods, that man who sits beside you..."
  },
  {
    id: "one-art",
    title: "One Art",
    author: "Elizabeth Bishop",
    date: "1976",
    tags: ["Favorites", "Loss"],
    stanzas: [
      [
        "The art of losing isn’t hard to master;",
        "so many things seem filled with the intent",
        "to be lost that their loss is no disaster."
      ],
      [
        "Lose something every day. Accept the fluster",
        "of lost door keys, the hour badly spent.",
        "The art of losing isn’t hard to master."
      ],
      [
        "Then practice losing farther, losing faster:",
        "places, and names, and where it was you meant",
        "to travel. None of these will bring disaster."
      ],
      [
        "I lost my mother’s watch. And look! my last, or",
        "next-to-last, of three loved houses went.",
        "The art of losing isn’t hard to master."
      ],
      [
        "I lost two cities, lovely ones. And, vaster,",
        "some realms I owned, two rivers, a continent.",
        "I miss them, but it wasn’t a disaster."
      ],
      [
        "—Even losing you (the joking voice, a gesture",
        "I love) I shan’t have lied. It’s evident",
        "the art of losing’s not too hard to master",
        "though it may look like (Write it!) like a disaster."
      ]
    ],
    excerpt: "The art of losing isn’t hard to master..."
  },
  {
    id: "when-you-are-old",
    title: "When You Are Old",
    author: "W.B. Yeats",
    date: "1892",
    tags: ["Favorites", "Love"],
    stanzas: [
      [
        "When you are old and grey and full of sleep,",
        "And nodding by the fire, take down this book,",
        "And slowly read, and dream of the soft look",
        "Your eyes had once, and of their shadows deep;"
      ],
      [
        "How many loved your moments of glad grace,",
        "And loved your beauty with love false or true,",
        "But one man loved the pilgrim soul in you,",
        "And loved the sorrows of your changing face;"
      ],
      [
        "And bending down beside the glowing bars,",
        "Murmur, a little sadly, how Love fled",
        "And paced upon the mountains overhead",
        "And hid his face amid a crowd of stars."
      ]
    ],
    excerpt: "When you are old and grey and full of sleep..."
  },
  {
    id: "neutral-tones",
    title: "Neutral Tones",
    author: "Thomas Hardy",
    date: "1867",
    tags: ["Favorites", "Memory"],
    stanzas: [
      [
        "We stood by a pond that winter day,",
        "And the sun was white, as though chidden of God,",
        "And a few leaves lay on the starving sod;",
        "– They had fallen from an ash, and were gray."
      ],
      [
        "Your eyes on me were as eyes that rove",
        "Over tedious riddles of years ago;",
        "And some words played between us to and fro",
        "On which lost the more by our love."
      ],
      [
        "The smile on your mouth was the deadest thing",
        "Alive enough to have strength to die;",
        "And a grin of bitterness swept thereby",
        "Like an ominous bird a-wing..."
      ],
      [
        "Since then, keen lessons that love deceives,",
        "And wrings with wrong, have shaped to me",
        "Your face, and the God-curst sun, and a tree,",
        "And a pond edged with grayish leaves."
      ]
    ],
    excerpt: "We stood by a pond that winter day..."
  },

  {
    id: "bright-star",
    title: "Bright Star",
    author: "John Keats",
    date: "1819",
    tags: ["Favorites", "Love"],
    stanzas: [
      [
        "Bright star, would I were stedfast as thou art—",
        "Not in lone splendour hung aloft the night",
        "And watching, with eternal lids apart,",
        "Like nature’s patient, sleepless Eremite,",
        "The moving waters at their priestlike task",
        "Of pure ablution round earth’s human shores,",
        "Or gazing on the new soft-fallen mask",
        "Of snow upon the mountains and the moors—"
      ],
      [
        "No—yet still stedfast, still unchangeable,",
        "Pillow’d upon my fair love’s ripening breast,",
        "To feel for ever its soft fall and swell,",
        "Awake for ever in a sweet unrest,",
        "Still, still to hear her tender-taken breath,",
        "And so live ever—or else swoon to death."
      ]
    ],
    excerpt: "Bright star, would I were stedfast as thou art—"
  },
  {
    id: "sonnet-116",
    title: "Sonnet 116",
    author: "William Shakespeare",
    date: "1609",
    tags: ["Favorites", "Classic"],
    stanzas: [
      [
        "Let me not to the marriage of true minds",
        "Admit impediments. Love is not love",
        "Which alters when it alteration finds,",
        "Or bends with the remover to remove."
      ],
      [
        "O no! it is an ever-fixed mark",
        "That looks on tempests and is never shaken;",
        "It is the star to every wand'ring bark,",
        "Whose worth's unknown, although his height be taken."
      ],
      [
        "Love's not Time's fool, though rosy lips and cheeks",
        "Within his bending sickle's compass come;",
        "Love alters not with his brief hours and weeks,",
        "But bears it out even to the edge of doom."
      ],
      [
        "If this be error and upon me prov'd,",
        "I never writ, nor no man ever lov'd."
      ]
    ],
    excerpt: "Let me not to the marriage of true minds..."
  },

  {
    id: "if",
    title: "If—",
    author: "Rudyard Kipling",
    date: "1910",
    tags: ["Favorites", "Wisdom"],
    stanzas: [
      [
        "If you can keep your head when all about you",
        "Are losing theirs and blaming it on you,",
        "If you can trust yourself when all men doubt you,",
        "But make allowance for their doubting too;",
        "If you can wait and not be tired by waiting,",
        "Or being lied about, don’t deal in lies,",
        "Or being hated, don’t give way to hating,",
        "And yet don’t look too good, nor talk too wise:"
      ],
      [
        "If you can dream—and not make dreams your master;",
        "If you can think—and not make thoughts your aim;",
        "If you can meet with Triumph and Disaster",
        "And treat those two impostors just the same;",
        "If you can bear to hear the truth you’ve spoken",
        "Twisted by knaves to make a trap for fools,",
        "Or watch the things you gave your life to, broken,",
        "And stoop and build ’em up with worn-out tools:"
      ],
      [
        "If you can make one heap of all your winnings",
        "And risk it on one turn of pitch-and-toss,",
        "And lose, and start again at your beginnings",
        "And never breathe a word about your loss;",
        "If you can force your heart and nerve and sinew",
        "To serve your turn long after they are gone,",
        "And so hold on when there is nothing in you",
        "Except the Will which says to them: ‘Hold on!’"
      ],
      [
        "If you can talk with crowds and keep your virtue,",
        "Or walk with Kings—nor lose the common touch,",
        "If neither foes nor loving friends can hurt you,",
        "If all men count with you, but none too much;",
        "If you can fill the unforgiving minute",
        "With sixty seconds’ worth of distance run,",
        "Yours is the Earth and everything that’s in it,",
        "And which is more—you’ll be a Man, my son!"
      ]
    ],
    excerpt: "If you can keep your head when all about you are losing theirs..."
  },
  {
    id: "do-not-go-gentle-into-that-good-night",
    title: "Do Not Go Gentle Into That Good Night",
    author: "Dylan Thomas",
    date: "1951",
    tags: ["Favorites", "Defiance"],
    stanzas: [
      [
        "Do not go gentle into that good night,",
        "Old age should burn and rave at close of day;",
        "Rage, rage against the dying of the light."
      ],
      [
        "Though wise men at their end know dark is right,",
        "Because their words had forked no lightning they",
        "Do not go gentle into that good night."
      ],
      [
        "Good men, the last wave by, crying how bright",
        "Their frail deeds might have danced in a green bay,",
        "Rage, rage against the dying of the light."
      ],
      [
        "Wild men who caught and sang the sun in flight,",
        "And learn, too late, they grieved it on its way,",
        "Do not go gentle into that good night."
      ],
      [
        "Grave men, near death, who see with blinding sight",
        "Blind eyes could blaze like meteors and be gay,",
        "Rage, rage against the dying of the light."
      ],
      [
        "And you, my father, there on the sad height,",
        "Curse, bless, me now with your fierce tears, I pray.",
        "Do not go gentle into that good night.",
        "Rage, rage against the dying of the light."
      ]
    ],
    excerpt: "Do not go gentle into that good night, old age should burn..."
  }
];

/**
 * Archived Template Poems
 * Preserved text-wise in the repository, but excluded from active website feed.
 */
const ARCHIVED_TEMPLATE_POEMS = [
  {
    id: "echoes-in-glass",
    title: "Echoes in Glass",
    date: "2026-07-28",
    tags: ["Reflections", "Time", "Shorts"],
    stanzas: [
      [
        "We built our houses out of light,",
        "And wondered why the evening fell,",
        "Dividing quiet from the night,",
        "Like water inside an old brass bell."
      ],
      [
        "A single breath across the pane,",
        "Translates the cold into a leaf,",
        "We trace the silver lines of rain,",
        "And measure winter by its grief."
      ],
      [
        "Yet somewhere in the refraction lies",
        "The morning we forgot to keep—",
        "Unopened under heavy skies,",
        "A promise sleeping, calm and deep."
      ]
    ],
    excerpt: "We built our houses out of light, and wondered why the evening fell..."
  },
  {
    id: "midnight-constellations",
    title: "Midnight Constellations",
    date: "2026-06-14",
    tags: ["Cosmos", "Existential"],
    stanzas: [
      [
        "The atlas opens on the desk,",
        "Unfolding stars we cannot reach,",
        "A geometry so picturesque,",
        "It silences our human speech."
      ],
      [
        "We trace Orion with a thumbnail,",
        "And count the light-years in between,",
        "Along the quiet, dusty rail",
        "Where memory and night convene."
      ],
      [
        "What is a name unto a star",
        "That burned out ten millenniums past?",
        "We glow briefly where we are,",
        "And hope the quiet song will last."
      ]
    ],
    excerpt: "The atlas opens on the desk, unfolding stars we cannot reach..."
  },
  {
    id: "harbor-at-dawn",
    title: "Harbor at Dawn",
    date: "2026-05-02",
    tags: ["Nature", "Morning"],
    stanzas: [
      [
        "Salt on the timber, mist on the bay,",
        "The tide recedes without a sound,",
        "And pulls the shadows of yesterday",
        "Deep underneath the gray profound."
      ],
      [
        "A lone seagull cuts through the haze,",
        "Its wings a silver crescent arc,",
        "Guiding the sun’s soft golden rays",
        "To break the silence of the dark."
      ],
      [
        "The wooden piers begin to hum,",
        "As morning wakes the sleeping fleet,",
        "And softly, as the day has come,",
        "The earth begins beneath our feet."
      ]
    ],
    excerpt: "Salt on the timber, mist on the bay, the tide recedes without a sound..."
  },
  {
    id: "the-craftsman",
    title: "The Craftsman’s Bench",
    date: "2026-03-19",
    tags: ["Memory", "Craft"],
    stanzas: [
      [
        "Pine shavings curl upon the floor,",
        "Like ribbons left from yesterday,",
        "He planes the grain of cedar door",
        "To smooth the roughness all away."
      ],
      [
        "In every ring of amber wood,",
        "A summer lived, a winter passed,",
        "He works until the shape is good,",
        "And built for years intended to last."
      ],
      [
        "His hands remember what the mind",
        "Forgets in rush of modern years:",
        "That beauty is the calm defined",
        "Between the patience and the tears."
      ]
    ],
    excerpt: "Pine shavings curl upon the floor, like ribbons left from yesterday..."
  },
  {
    id: "autumn-soliloquy",
    title: "Autumn Soliloquy",
    date: "2025-11-10",
    tags: ["Nature", "Reflections"],
    stanzas: [
      [
        "Leaves fall like amber letters sent",
        "From branches learning to let go,",
        "The canopy is thinned and spent,",
        "Preparing for the quiet snow."
      ],
      [
        "Walk slow along the rustling path,",
        "Listen to what the earth would say,",
        "There is no loss in winter's wrath,",
        "Only a breath before the May."
      ]
    ],
    excerpt: "Leaves fall like amber letters sent from branches learning to let go..."
  }
];
